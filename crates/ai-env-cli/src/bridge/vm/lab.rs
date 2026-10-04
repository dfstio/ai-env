//! The live platform probes `ai-env lab run` drives (plan S4 §8; S5; S6): each
//! starts its own VMs (label `probe:<name>`; max duration 900 s and audited
//! internet egress unless the probe sets its own: S5's dns-path and
//! connector-pending on vpc; S6's e1 1200 s with max idle 1200 s, e5 and
//! clock-after-resume 2400 s with 1500 s suspended (e5 max idle 60 s,
//! clock-after-resume on vpc), in-vm-firewall a default and a `--shell` VM),
//! measures, and terminates every VM it started on every path — success,
//! failure, error or Ctrl-C — before the verdict is recorded (a Ctrl-C
//! records nothing and exits 3).
use crate::bridge::agent::conn::{AgentConn, HelloOk};
use crate::bridge::agent::{run_spawn, spawn_channels, AgentEnv, AgentTarget, RemoteExit, RunPolicy, SpawnEvent, SpawnInput, SpawnSpec, Start};
use crate::bridge::api::{AuthToken, EndpointClient, HealthDetailReply, IdleSpec, MicrovmApi, VmInfo, VmState, APP_PORT};
use crate::bridge::awscli;
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::{self, AgentDial, ShellAuth, UpgradeAuth, UpgradeProbe};
use crate::bridge::vm::cmd::Ctx;
use crate::bridge::vm::registry::{self, RowStatus, VmRow};
use crate::bridge::vm::{health, run, shell, token};
use crate::bridge::{egress, probes};
use crate::wire::frame::{Deliver, Frame, HealthDetail, ResumePoint, ResumeStatus, RunHookPayload, Scope, Sig, SpawnId, CHUNK_MAX, CLOSE_NORMAL};
use crate::wire::redact::{register_secret, Secret};
use crate::wire::time::{unix_now, unix_now_ms};
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// What a live probe measured.
#[derive(Debug, Clone, Default)]
pub struct ProbeOutcome {
    pub verdict: String,
    pub note: String,
    pub claude: Option<String>,
    pub shim: Option<String>,
    pub image_version: Option<String>,
}

/// What a probe started, for the terminate guard: the VMs, and the client
/// token of every run it made, so a Ctrl-C between RunMicrovm and the VM's
/// id still finds that VM (as `vm smoke` finds its own run).
#[derive(Debug, Default)]
struct Started {
    ids: Vec<String>,
    tokens: Vec<String>,
}

impl Started {
    fn push(&mut self, id: String) {
        if !self.ids.contains(&id) {
            self.ids.push(id);
        }
    }

    /// `p` with a client token of its own (a fresh uuid v7), kept for [`sweep_own`].
    fn own(&mut self, p: &run::RunPlan) -> run::RunPlan {
        let token = uuid::Uuid::now_v7().to_string();
        self.tokens.push(token.clone());
        run::RunPlan { client_token: Some(token), ..p.clone() }
    }
}

/// Run the live probe `name`; `arg` is its positional argument (the
/// connector ARN of `connector-pending`, already validated by `lab run`). A
/// Ctrl-C ends the probe, never the terminate guard: the VMs it started (and
/// one its cut caught starting, [`sweep_own`]) are ended, then `Cancelled`
/// (exit 3) and nothing is recorded.
pub async fn run_probe<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, name: &str, arg: Option<&str>) -> Result<ProbeOutcome, BridgeError> {
    let since = unix_now();
    let mut started = Started::default();
    let probe = async {
        match name {
            "payload-size" => payload_size(ctx, api, ep, &mut started).await,
            "no-traffic-before-run" => no_traffic_before_run(ctx, api, ep, &mut started).await,
            "snapshot-uniqueness" => snapshot_uniqueness(ctx, api, ep, &mut started).await,
            "idle-policy-limits" => idle_policy_limits(ctx, api, ep, &mut started).await,
            "connector-pending" => connector_pending(ctx, api, ep, arg, &mut started).await,
            "dns-path" => dns_path(ctx, api, ep, &mut started).await,
            // S6: each owns its VMs on the lab path with its own budget and terminate guard.
            "e0" => e0(ctx, api, ep, &mut started).await,
            "e1" => e1(ctx, api, ep, &mut started).await,
            "e5" => e5(ctx, api, ep, &mut started).await,
            "frames" => frames(ctx, api, ep, &mut started).await,
            "reattach" => reattach(ctx, api, ep, &mut started).await,
            "clock-after-resume" => clock_after_resume(ctx, api, ep, &mut started).await,
            "in-vm-firewall" => in_vm_firewall(ctx, api, ep, &mut started).await,
            other => Err(BridgeError::Config(format!("{other} is not a live probe"))),
        }
    };
    // Polled first, so the handler is in place before the probe's first call (a Ctrl-C is never the default death).
    let result = tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => Err(BridgeError::Cancelled),
        r = probe => r,
    };
    if matches!(result, Err(BridgeError::Cancelled)) {
        eprintln!("lab: cancelled: ending every VM this probe started");
        sweep_own(ctx, api, ep, &mut started, since).await;
    }
    // The terminate guard: every VM this probe started, whatever happened.
    for id in &started.ids {
        match run::terminate_and_record(api, &ctx.paths, id, "probe", Some(run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms))).await {
            Ok(_) => eprintln!("lab: terminated {id}"),
            Err(e) => eprintln!("lab: could not terminate {id}: {e} — run: ai-env vm terminate {id}"),
        }
    }
    result
}

/// After a Ctrl-C: the VMs of this probe's runs that `started` does not hold
/// yet (the cut came between RunMicrovm and the id), found only through the
/// rows carrying the probe's own client tokens, as `vm smoke` finds its own:
/// a live id row is that VM; a pending row goes through the adoption sweep.
/// Another run's rows never match.
async fn sweep_own<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started, since: u64) {
    let Ok(rows) = registry::list_rows(&ctx.paths) else { return };
    for token in started.tokens.clone() {
        let mine: Vec<&VmRow> = rows.iter().filter(|r| r.client_token == token).collect();
        if let Some(r) = mine.iter().find(|r| !r.is_pending_row() && r.status != RowStatus::Terminated) {
            started.push(r.id.clone());
        } else if let Some(pending) = mine.iter().find(|r| r.is_pending_row()) {
            adopt_into(ctx, api, ep, pending, since, started).await;
        }
    }
}

fn flags(name: &str, max_duration_s: u32, idle_s: Option<u32>, suspended_s: Option<u32>, wait: bool) -> run::RunFlags {
    run::RunFlags {
        max_duration_s: Some(max_duration_s),
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
/// have created (the adoption sweep). The run gets a client token of its own
/// first ([`Started::own`]).
async fn start<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, p: &run::RunPlan, started: &mut Started) -> Result<VmInfo, BridgeError> {
    let since = unix_now();
    let p = started.own(p);
    match run::select_vm_detailed(api, &ctx.paths, &p, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms)).await {
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

async fn guard_failure<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, f: &run::SelectFailure, since: u64, started: &mut Started) {
    if let Some(id) = &f.started {
        started.push(id.clone());
    }
    if let Some(pending) = &f.kept_pending {
        adopt_into(ctx, api, ep, pending, since, started).await;
    }
}

/// The VM a kept pending row stands for, by the adoption sweep, into `started`.
async fn adopt_into<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, pending: &VmRow, since: u64, started: &mut Started) {
    match run::adopt_after_ambiguous_for(api, ep, &ctx.paths, pending, since, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms), "probe").await {
        Ok(run::Adoption::Adopted(id)) => started.push(id),
        // The egress gate could not terminate the run's VM: the terminate guard tries again.
        Err(BridgeError::EgressMismatch(m)) if !m.terminated => started.push(m.id.clone()),
        _ => {}
    }
}

async fn payload_size<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let mut out = ProbeOutcome::default();
    let mut notes = Vec::new();
    let mut verdicts = Vec::new();
    for len in [RunHookPayload::MAX_BYTES, RunHookPayload::MAX_BYTES + 1] {
        let oversized = len > RunHookPayload::MAX_BYTES;
        // The normal placement path (count, pending row, adoption key) with the payload
        // padded to `len` bytes. The oversized run does not wait for RUNNING: the shim
        // refuses its /run (413), and the state that follows is what gets recorded.
        let mut p = plan(ctx, &flags("payload-size", 900, None, None, !oversized))?;
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

async fn no_traffic_before_run<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("no-traffic-before-run", 900, None, None, false))?;
    let t_run = Instant::now();
    let vm = start(ctx, api, ep, &p, started).await?;
    // The budget starts when RunMicrovm answered; the note counts from the call.
    let t0 = Instant::now();
    let id = vm.id.clone();
    let step = Duration::from_millis(ctx.knobs.backoff_ms.map_or(250, |ms| (ms / 4).max(1)));
    let budget = Duration::from_millis(ctx.knobs.backoff_ms.map_or(60_000, |ms| ms * 60));
    let (mut attempts, mut states, mut token) = (0u32, Vec::<String>::new(), None);
    let mut out = ProbeOutcome::default();
    // A first 200 before `/run` (live, 30 Sep 2026: the endpoint forwards while the control plane still says
    // PENDING) does not end the probe: it keeps asking until the shim has seen `/run`, to measure the window.
    // The window gets its own budget from that first answer, and at least five more asks (the knob-scaled test
    // budget is shorter than one ask under load).
    let mut before: Option<(u128, u32, String)> = None;
    let mut since = t0;
    while attempts == 0 || since.elapsed() < budget || before.as_ref().is_some_and(|(_, n, _)| attempts < n + 5) {
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
                    if !h.run_hook_seen {
                        if before.is_none() {
                            before = Some((t_run.elapsed().as_millis(), attempts, states.join("→")));
                            since = Instant::now();
                        }
                    } else {
                        out.verdict = if before.is_some() { "health-before-run" } else { "health-after-run" }.to_string();
                        let seen = format!("run_hook_seen {} ms after RunMicrovm was called, {attempts} attempts; states seen {}", t_run.elapsed().as_millis(), states.join("→"));
                        out.note = match &before {
                            Some((ms, n, st)) => format!("first 200 without /run {ms} ms after RunMicrovm was called ({n} attempts, states {st}); {seen}"),
                            None => format!("first 200 {seen}"),
                        };
                        return Ok(out);
                    }
                }
                Ok(r) if r.status == 401 || r.status == 403 => token = api.create_auth_token(&id, 5, APP_PORT).await.ok(),
                Ok(_) | Err(BridgeError::Endpoint(_)) => {}
                Err(e) => return Err(e),
            }
        }
        tokio::time::sleep(step).await;
    }
    if let Some((ms, n, st)) = before {
        out.verdict = "health-before-run".to_string();
        out.note = format!("first 200 without /run {ms} ms after RunMicrovm was called ({n} attempts, states {st}); run_hook_seen still false after {} s (states seen {})", budget.as_secs(), states.join("→"));
        return Ok(out);
    }
    Err(BridgeError::Sdk { op: "probe", message: format!("no /health 200 within {} s (states seen {})", budget.as_secs(), states.join("→")) })
}

async fn snapshot_uniqueness<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("snapshot-uniqueness", 900, None, None, true))?;
    let poll = run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms);
    let since = unix_now();
    let (pa, pb) = (started.own(&p), started.own(&p));
    let (a, b) = tokio::join!(run::select_vm_detailed(api, &ctx.paths, &pa, poll), run::select_vm_detailed(api, &ctx.paths, &pb, poll));
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

async fn idle_policy_limits<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let mut parts = Vec::new();
    let mut notes = Vec::new();
    for suspended in [900u32, 86_400] {
        let p = plan(ctx, &flags("idle-policy-limits", 900, Some(300), Some(suspended), true))?;
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

/// connector-pending (S5): RunMicrovm against a connector that is not ACTIVE
/// yet (`make connector-probe` creates a throw-away one). First the
/// operator's view (the aws CLI, after the operator-account check): the
/// connector must be PENDING now, else nothing is recorded. The probe VM's
/// plan is `vpc` with exactly that ARN, so the echo gate compares with the
/// probe's own list; RunMicrovm's answer is what is measured, so the run does
/// not wait for RUNNING. Verdicts: `rejected:<Code>` for a refusal
/// (`probes::verdict_connector_rejected`; throttling, a quota or an access
/// denial is an error, nothing recorded); `accepted` when the VM echoed the
/// connector, at RunMicrovm and in its RUNNING answer; `accepted:internet`
/// when either echoed `INTERNET_EGRESS` instead and `accepted:echo-mismatch`
/// when either echoed anything else (at RunMicrovm the gate rejected the VM;
/// the gate knows only the configured connector's Id alias, so an Id-form
/// echo of the throw-away connector lands here);
/// `accepted:terminated` when the service ended the VM right after. The note
/// carries the echo and the connector's state before and after. Every VM it
/// started is ended by the terminate guard (or was by the gate). A failure
/// before RunMicrovm (the image version, the count) or an ambiguous one is
/// an error: nothing is recorded.
async fn connector_pending<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, arn: Option<&str>, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let arn = arn.map(str::trim).filter(|a| crate::bridge::config::is_connector_arn(a)).ok_or_else(|| BridgeError::Config("connector-pending needs the ARN of a connector that is not ACTIVE yet".into()))?;
    awscli::require_operator_account(arn).map_err(|e| BridgeError::Config(format!("connector-pending: {e}")))?;
    let (state, before) = connector_state(arn).map_err(|message| BridgeError::Sdk { op: "get_network_connector", message })?;
    if state != "PENDING" {
        return Err(BridgeError::Config(format!(
            "connector-pending: {arn} is {before}, not PENDING: nothing recorded (the probe measures RunMicrovm against a connector that is not ACTIVE yet; make connector-probe CONFIRM=create-probe-connector creates a fresh one)"
        )));
    }
    // Planned as internet (no configured connector needed), then given exactly the probe's connector.
    let mut f = flags("connector-pending", 900, None, None, false);
    f.egress = Some(run::Egress::Internet);
    let mut p = plan(ctx, &f)?;
    p.egress = run::Egress::Vpc;
    p.egress_connectors = vec![arn.to_string()];
    let p = started.own(&p);
    let since = unix_now();
    let shown = |l: &[String]| if l.is_empty() { "nothing".to_string() } else { l.join(", ") };
    let selected = run::select_vm_detailed(api, &ctx.paths, &p, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms)).await;
    let states = || {
        let after = connector_state(arn).map_or_else(|e| format!("unknown ({e})"), |(_, s)| s);
        format!("connector {before} before RunMicrovm, {after} after")
    };
    let accepted = |verdict: &str, note: String| ProbeOutcome { verdict: verdict.to_string(), note: format!("{note}; {}", states()), ..ProbeOutcome::default() };
    match selected {
        Ok(run::Selected::Started { vm, .. }) => {
            started.push(vm.id.clone());
            let t = Instant::now();
            // The RUNNING answer is judged as select judges it: its egress, when it reports one, must still be the ARN.
            let (verdict, after) = match run::wait_for_state(api, &vm.id, &VmState::Running, run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms)).await {
                Ok(running) if !running.egress.is_empty() && !echoes_only(&running.egress, arn) => {
                    (echo_verdict(&running.egress), format!("RUNNING {} ms later, echoing egress {} (not this ARN)", t.elapsed().as_millis(), shown(&running.egress)))
                }
                Ok(_) => ("accepted", format!("RUNNING {} ms later", t.elapsed().as_millis())),
                Err(e) => ("accepted", format!("not RUNNING: {e}")),
            };
            let out = accepted(verdict, format!("RunMicrovm accepted {arn} as {}: echoed egress {}; {after}", vm.id, shown(&vm.egress)));
            Ok(ProbeOutcome { image_version: Some(vm.image_version.clone()), ..out })
        }
        Ok(run::Selected::Reused { vm, .. }) => Err(BridgeError::Config(format!("the probe reused {} (internal)", vm.id))),
        Err(fail) => {
            guard_failure(ctx, api, ep, &fail, since, started).await;
            match fail.error {
                BridgeError::EgressMismatch(m) => {
                    let verdict = echo_verdict(&m.echoed);
                    let ended = if m.terminated { "terminated by the egress gate" } else { "left to the terminate guard" };
                    Ok(accepted(verdict, format!("RunMicrovm accepted {arn} as {}, which echoed egress {} (not this ARN in its name form: the gate rejected it; {ended})", m.id, shown(&m.echoed))))
                }
                // The service answered TERMINATING/TERMINATED (or never found the VM) after RunMicrovm returned it.
                BridgeError::Terminated(m) => Ok(accepted("accepted:terminated", format!("RunMicrovm accepted {arn}, then: {m}"))),
                // Before RunMicrovm (no pending row), or a failure the VM may outlive: not RunMicrovm's verdict.
                e if fail.client_token.is_none() || fail.started.is_some() || fail.kept_pending.is_some() => Err(e),
                e => match crate::bridge::probes::verdict_connector_rejected(&e) {
                    Some((verdict, note)) => Ok(ProbeOutcome { verdict, note: format!("{note}; {}", states()), ..ProbeOutcome::default() }),
                    // Throttling, a quota, the runtime policy, credentials: no verdict on the connector.
                    None => Err(e),
                },
            }
        }
    }
}

/// Is `echoed` exactly the probe's connector (name form, `:N` stripped)?
fn echoes_only(echoed: &[String], arn: &str) -> bool {
    crate::bridge::egress::ExpectedEcho::for_plan(run::Egress::Vpc, &[arn.to_string()]).is_some_and(|e| e.matches(echoed, None))
}

/// The verdict of an accepted run whose echo is not the probe's connector:
/// `accepted:internet` when it echoes `INTERNET_EGRESS`, else
/// `accepted:echo-mismatch`.
fn echo_verdict(echoed: &[String]) -> &'static str {
    let internet = crate::bridge::egress::normalize_connector(&crate::bridge::egress::internet_egress_arn());
    if echoed.iter().any(|e| crate::bridge::egress::normalize_connector(e) == internet) {
        "accepted:internet"
    } else {
        "accepted:echo-mismatch"
    }
}

/// The connector's `State` as the operator's aws CLI reads it (`aws
/// lambda-core get-network-connector`, region and endpoint pinned), and
/// that state with its reason for the note.
fn connector_state(arn: &str) -> Result<(String, String), String> {
    let doc = awscli::aws_json("lambda-core", &["get-network-connector", "--identifier", arn])?;
    let state = doc.get("State").and_then(|s| s.as_str()).unwrap_or_default().to_string();
    if state.is_empty() {
        return Err(format!("aws lambda-core get-network-connector: no State for {arn}"));
    }
    let reason: Vec<&str> = ["StateReasonCode", "StateReason"].iter().filter_map(|k| doc.get(*k).and_then(|v| v.as_str())).map(str::trim).filter(|s| !s.is_empty()).collect();
    let shown = if reason.is_empty() { state.clone() } else { format!("{state} ({})", reason.join(": ")) };
    Ok((state, shown))
}

/// The dns-path row's note: the verdict's note, what the run asked, the VM, and, only for a transcript the knob
/// supplied, `check::FAKE_SHELL_NOTE`, which keeps the row from ever deciding the newest dns-path verdict
/// (`egress::newest_dns_path_row`).
fn dns_path_note(derived: &str, nonce: &str, vm_id: &str, from_knob: bool) -> String {
    use crate::bridge::egress::check;
    let knob = if from_knob { format!("; {}", check::FAKE_SHELL_NOTE) } else { String::new() };
    format!("{derived}; asked {} A, and example.com A of each server that replied ({vm_id}){knob}", check::dns_name(nonce))
}

/// dns-path (S5): from a `--egress vpc --shell` VM, which DNS server (if any)
/// answers a fresh name that exists nowhere (`egress::check::dns_name`):
/// `no-dns`; `platform-dns:<ips>` (platform resolvers replied only with an
/// empty NOERROR — no answer, no authority — and no address for
/// example.com: the platform's stub, which `[egress].accept_platform_dns`
/// may accept by name); `platform-dns-answered:<ips>` (any other platform
/// reply: a failing verdict); `platform-dns-resolves:<ips>` (a platform
/// resolver returned an address: a failing verdict); `open-dns:<ips>` (a
/// public one, or any other, replied: a failing verdict) — every server of
/// the worst class, in case order. Once the VM's `/health` answered, through
/// the scripted shell: `/etc/resolv.conf`'s nameserver, 1.1.1.1 (and OpenDNS
/// on UDP 443), the link-local resolver (169.254.169.253, `fd00:ec2::253`),
/// the VPC's and the VM subnet's +2 are asked over UDP and TCP — the fresh
/// name with dig's header, then example.com of each server that replied —
/// between two `allowed` cases through the proxy that must both answer 401
/// (a VM without working networking would read as `no-dns`); the note
/// carries `resolves=yes|no`, the resolv.conf nameserver, each server's
/// status and counts, and the name asked (`egress::check::dns_path_outcome`).
/// Under the file-backed fake it refuses (exit 9) after starting its VM and
/// before any shell token or dial, unless — debug builds — the transcript
/// knob stands in for the shell, as for `egress check`
/// (`egress::check::fake_transcript`): its row's note then ends with
/// `check::FAKE_SHELL_NOTE`, so the readers of the newest dns-path verdict
/// skip it; the terminate guard ends the VM.
async fn dns_path<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    use crate::bridge::egress::check;
    if ctx.cfg.aws.egress_connector_arn.as_deref().is_none_or(|a| a.trim().is_empty()) {
        return Err(BridgeError::Config("dns-path needs [aws].egress_connector_arn (a vpc VM): run `make infra-status WRITE=1`".into()));
    }
    let mut f = flags("dns-path", 900, None, None, true);
    f.egress = Some(run::Egress::Vpc);
    f.shell = true;
    let p = plan(ctx, &f)?;
    let vm = start(ctx, api, ep, &p, started).await?;
    health::read_health(api, ep, &ctx.paths, &vm.id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
    // Where the transcript comes from, decided once: under the fake only the knob's file (debug builds) can supply one,
    // and the same flag marks the row (`dns_path_note`).
    let from_knob = ctx.knobs.fake_api.is_some();
    let (nonce, output) = if from_knob {
        check::fake_transcript("dns-path")?
    } else {
        let nonce = check::new_nonce();
        let script = check::render_dns_script(&nonce, &check::proxy_ip(&ctx.cfg, &ctx.paths));
        let output = shell::run_script(api, &vm.id, &script, check::script_budget(check::DNS_PATH_CASES.len()), ShellAuth::Header).await?;
        (nonce, output)
    };
    let markers = check::parse_markers(&output, &nonce).map_err(|e| BridgeError::Protocol(format!("dns-path: the shell transcript: {e}")))?;
    let (verdict, note) = check::dns_path_outcome(&markers).map_err(|message| BridgeError::Sdk { op: "probe", message: format!("dns-path on {}: {message}", vm.id) })?;
    Ok(ProbeOutcome {
        verdict,
        note: dns_path_note(&note, &nonce, &vm.id, from_knob),
        image_version: Some(vm.image_version.clone()),
        ..ProbeOutcome::default()
    })
}

// ---- S6: the agent-transport probes (e0, e1, e5, frames, reattach, clock-after-resume, in-vm-firewall) ----
//
// Each starts its own lab VM(s) with its own budget, reads `/health` to fill
// the ProbeOutcome, builds the agent target from the VM's row
// (`AgentTarget::from_row`), and talks to the real shim through the endpoint
// (never the control-plane fake, which has no shim behind it: under
// `AI_ENV_BRIDGE_LAB_FAKE_API` every S6 probe refuses with
// [`s6_fake_refusal`] after its VM is started, so the lifecycle and the
// terminate guard are still exercised). The verdict renderers live in
// `bridge::probes`.

/// Where `/agent` is dialed: the debug knob's loopback address when set (a
/// test's native shim), else `wss://<endpoint>:443`.
fn agent_dial(ctx: &Ctx) -> AgentDial {
    AgentDial { local: ctx.knobs.agent_addr().ok().flatten() }
}

/// The refusal an S6 probe returns under the file-backed fake (exit 9): there
/// is no shim behind the fake's endpoint, so the agent transport cannot run.
fn s6_fake_refusal(name: &str) -> BridgeError {
    BridgeError::Policy(format!("lab run {name}: the file-backed fake has no shim behind its endpoint (AI_ENV_BRIDGE_LAB_FAKE_API is set): the agent transport needs the real service"))
}

fn terminated(vm: &VmInfo) -> BridgeError {
    BridgeError::Terminated(format!("{} is {}", vm.id, vm.state.as_str()))
}

/// Start one S6 probe VM (into the terminate guard), read its `/health` (for
/// the ProbeOutcome claude/shim/image_version), and build its agent target
/// from the row the run wrote (the session token lives only there). Every S6
/// VM but in-vm-firewall's `--shell` one is a default row, so no lab spawn
/// (`run_spawn` or a raw `spawn` frame) runs on a shell row:
/// [`in_vm_firewall_shell`] alone clears `shell` on its own VM's target.
async fn s6_start<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, p: &run::RunPlan, started: &mut Started) -> Result<(VmInfo, VmRow, AgentTarget, ProbeOutcome), BridgeError> {
    let vm = start(ctx, api, ep, p, started).await?;
    let (h, _) = health::read_health(api, ep, &ctx.paths, &vm.id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
    let out = ProbeOutcome { claude: h.claude_version.clone(), shim: Some(h.shim_version.clone()), image_version: Some(vm.image_version.clone()), ..ProbeOutcome::default() };
    let row = registry::read_row(&ctx.paths, &vm.id)?.ok_or_else(|| BridgeError::Config(format!("{} has no registry row after starting (internal)", vm.id)))?;
    let target = AgentTarget::from_row(&row)?;
    Ok((vm, row, target, out))
}

/// How long a probe waits for `hello_ok` once the socket upgraded. The
/// socket's dial is already bounded (`transport::AGENT_DIAL_TIMEOUT`), but
/// `conn.hello` does a bare `recv` (its doc: "the caller bounds the wait for
/// the answer"): a shim that completes the 101 and then never sends
/// `hello_ok` — overload, a bug, the hold during auto-resume, the 8/9-socket
/// cap stalling the connection task — would otherwise hang the probe, so the
/// terminate guard cannot run until the VM is reclaimed at its max duration.
/// Bounded like the session's `dead_after` ([`crate::wire::frame::DEAD_AFTER`]),
/// scaled by the lab backoff knob.
fn hello_wait(ctx: &Ctx) -> Duration {
    let d = crate::wire::frame::DEAD_AFTER;
    ctx.knobs.backoff_ms.map_or(d, |ms| Duration::from_millis((d.as_millis() as u64).saturating_mul(ms) / 1000).max(Duration::from_millis(1)))
}

/// `hello` on an open socket, bounded by `wait`: a `hello_ok` that never
/// arrives is a transport error, not a hang (see [`hello_wait`]).
async fn hello_bounded(conn: &mut AgentConn, target: &AgentTarget, resume: Vec<ResumePoint>, idle_s: Option<u32>, wait: Duration) -> Result<HelloOk, BridgeError> {
    match tokio::time::timeout(wait, conn.hello(&target.session_token, resume, idle_s)).await {
        Ok(r) => r,
        Err(_) => Err(BridgeError::Transport(format!("no hello_ok from {} within {wait:?}", target.vm_id))),
    }
}

/// Open one `/agent` socket as this Mac and complete `hello` (resuming
/// `resume`), with the shim idle timeout `idle_s`; `wait` bounds the wait for
/// `hello_ok` ([`hello_bounded`]).
async fn open_hello(dial: &AgentDial, target: &AgentTarget, token: &Secret<String>, resume: Vec<ResumePoint>, idle_s: Option<u32>, wait: Duration) -> Result<(AgentConn, HelloOk), BridgeError> {
    let mut conn = AgentConn::open(dial, &target.endpoint, token).await.map_err(|e| BridgeError::Endpoint(format!("/agent dial to {}: {e}", target.vm_id)))?;
    let ok = hello_bounded(&mut conn, target, resume, idle_s, wait).await?;
    Ok((conn, ok))
}

/// Read one spawn's `spawned` (its pid) on an open socket, or the first other
/// terminal answer, within `budget`.
async fn await_spawned(conn: &mut AgentConn, sid: &SpawnId, budget: Duration) -> Result<u32, BridgeError> {
    let deadline = Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(BridgeError::Protocol(format!("no spawned for {sid} within {} s", budget.as_secs())));
        }
        match tokio::time::timeout(left, conn.recv()).await {
            Ok(Ok(Some(Frame::Spawned { spawn_id, pid, .. }))) if spawn_id == *sid => return Ok(pid),
            Ok(Ok(Some(Frame::SpawnErr { spawn_id, code, message }))) if spawn_id == *sid => return Err(BridgeError::Protocol(format!("spawn {sid} refused ({code:?}): {message}"))),
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => return Err(BridgeError::Transport(format!("socket closed before spawned for {sid}"))),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(BridgeError::Protocol(format!("no spawned for {sid} within {} s", budget.as_secs()))),
        }
    }
}

/// One `GET /health/detail` with the Port(8080) token and the session bearer.
async fn detail_via<E: EndpointClient>(ep: &E, target: &AgentTarget, token: &AuthToken) -> Result<HealthDetailReply, BridgeError> {
    ep.get_health_detail(&target.endpoint, token, &target.session_token).await
}

/// `spec` as the agent through one `run_spawn` (the session mints its own
/// Port(8080) tokens), feeding `stdin` then EOF and consuming every chunk as
/// it arrives: (stdout, stderr, pid, exit).
async fn exec_agent<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, spec: SpawnSpec, stdin: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, Option<u32>, RemoteExit), BridgeError> {
    let (out, err, pid, exit) = exec_agent_partial(env, spec, stdin).await;
    Ok((out, err, pid, exit?))
}

/// [`exec_agent`], keeping what arrived when the session ends in an error:
/// (stdout, stderr, pid, the exit or that error).
async fn exec_agent_partial<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, spec: SpawnSpec, stdin: Vec<u8>) -> (Vec<u8>, Vec<u8>, Option<u32>, Result<RemoteExit, BridgeError>) {
    let (io, c) = spawn_channels(16);
    let feed = c.input.clone();
    let feeder = tokio::spawn(async move {
        for chunk in stdin.chunks(CHUNK_MAX) {
            if feed.send(SpawnInput::Stdin(chunk.to_vec())).await.is_err() {
                return;
            }
        }
        let _ = feed.send(SpawnInput::StdinEof).await;
    });
    let mut events = c.events;
    let consumed = c.consumed.clone();
    let consumer = tokio::spawn(async move {
        let (mut out, mut err, mut pid) = (Vec::new(), Vec::new(), None);
        while let Some(ev) = events.recv().await {
            match ev {
                SpawnEvent::Started { pid: p, .. } => pid = Some(p),
                SpawnEvent::Stdout { seq, bytes } => {
                    out.extend_from_slice(&bytes);
                    consumed.stdout_done(seq);
                }
                SpawnEvent::Stderr { seq, bytes, .. } => {
                    err.extend_from_slice(&bytes);
                    consumed.stderr_done(seq);
                }
                SpawnEvent::Note(_) | SpawnEvent::Link(_) | SpawnEvent::Exit(_) => {}
            }
        }
        (out, err, pid)
    });
    let outcome = run_spawn(env, Start::New(spec), io).await;
    drop(c.input);
    drop(c.control);
    feeder.abort();
    match consumer.await {
        Ok((out, err, pid)) => (out, err, pid, outcome.map(|o| o.exit)),
        Err(e) => (Vec::new(), Vec::new(), None, Err(BridgeError::Transport(format!("agent consumer task: {e}")))),
    }
}

// ---- e0 ------------------------------------------------------------------------------------

/// Did e0's upgrade open a WebSocket: a 101 the client took (no refusal, a
/// socket)? A 101 it refused — a `Connection` other than `Upgrade`, a bad
/// `Sec-WebSocket-Accept`, an unrequested subprotocol — opened nothing.
fn upgraded(p: &UpgradeProbe) -> bool {
    p.status == 101 && p.refused.is_none() && p.socket.is_some()
}

async fn e0<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("e0", 900, None, None, true))?;
    let (vm, _row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(s6_fake_refusal("e0"));
    }
    let dial = agent_dial(ctx);
    let wait = hello_wait(ctx);
    let ep_host = target.endpoint.clone();
    let mut notes = Vec::new();

    // 1) a Port(8080) header token → a 101 the client takes (the HTTP version is the client's parse).
    let tok8080 = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 5).await?;
    let header = transport::upgrade_probe(&dial, &ep_host, UpgradeAuth::Header { token: tok8080.value()?.clone(), port: APP_PORT }).await?;
    let accepted = upgraded(&header);
    if let Some(r) = &header.refused {
        notes.push(format!("the client refused the header token's {}: {r}", header.status));
    }
    drop(header.socket);
    // 2) no token → 403.
    let no_token = transport::upgrade_probe(&dial, &ep_host, UpgradeAuth::None).await?;
    // 3) a Port(8081) token presented on 8080 → 403 (minted directly: check_port forbids 8081).
    let (_other_port_label, other_token) = match api.create_auth_token(&vm.id, 5, 8081).await {
        Ok(t) => {
            register_secret(t.value()?.expose());
            (8081u16, t)
        }
        Err(e) => {
            notes.push(format!("a Port(8081) token was refused ({e}); used Port(8082)"));
            let t = token::mint(api, &ctx.paths, &vm.id, 8082, 5).await?;
            (8082u16, t)
        }
    };
    let other = transport::upgrade_probe(&dial, &ep_host, UpgradeAuth::Header { token: other_token.value()?.clone(), port: APP_PORT }).await?;
    // 4) a Port(9418) token with x-aws-proxy-port 8080 → 403.
    let tok9418 = token::mint(api, &ctx.paths, &vm.id, 9418, 5).await?;
    let proxy = transport::upgrade_probe(&dial, &ep_host, UpgradeAuth::Header { token: tok9418.value()?.clone(), port: APP_PORT }).await?;

    out.verdict = probes::verdict_e0(header.status, accepted, &header.version, no_token.status, other.status, proxy.status);

    // The subprotocol form.
    let sub = transport::upgrade_probe(&dial, &ep_host, UpgradeAuth::Subprotocol { token: tok8080.value()?.clone(), port: APP_PORT }).await;
    let sub_note = match sub {
        Ok(p) => {
            drop(p.socket);
            format!("subprotocol form: HTTP {}{}", p.status, p.refused.map(|r| format!(" (client refused: {r})")).unwrap_or_default())
        }
        Err(e) => format!("subprotocol form: {e}"),
    };
    // The bearer through the endpoint (Authorization passes the proxy): /health/detail with the session bearer → 200.
    let bearer = detail_via(ep, &target, &tok8080).await.map_or_else(|e| format!("bearer /health/detail: {e}"), |d| format!("bearer /health/detail: HTTP {}", d.status));

    let sockets = e0_sockets(ep, &dial, &target, &tok8080, wait).await?;
    notes.push(format!("{sub_note}; {bearer}; {sockets}"));
    out.note = notes.join("; ");
    Ok(out)
}

/// e0's 9th socket (critic L3): eight sockets each complete `hello` and stay
/// open, then a 9th opens; its answer (the endpoint's cap of 8 connections
/// per VM, or the shim's) goes in the note. Then the shim's socket count
/// from `/health/detail`, read once the 9th and one held socket closed: with
/// all eight held the endpoint's cap would likely refuse the read itself
/// (`?`). The note says which count it is: the held sockets still open.
async fn e0_sockets<E: EndpointClient>(ep: &E, dial: &AgentDial, target: &AgentTarget, tok: &AuthToken, wait: Duration) -> Result<String, BridgeError> {
    let mut held = Vec::new();
    let mut short = String::new();
    for i in 0..8 {
        match open_hello(dial, target, tok.value()?, vec![], Some(3600), wait).await {
            Ok((conn, _)) => held.push(conn),
            Err(e) => {
                short = format!(" (socket {} failed: {e})", i + 1);
                break;
            }
        }
    }
    let opened = held.len();
    let ninth = match AgentConn::open(dial, &target.endpoint, tok.value()?).await {
        Ok(mut conn) => {
            let said = match hello_bounded(&mut conn, target, vec![], Some(3600), wait).await {
                Ok(_) => "the 9th socket completed hello (no cap hit)".to_string(),
                Err(e) => format!("the 9th socket's hello: {e}"),
            };
            conn.close(CLOSE_NORMAL).await;
            said
        }
        Err(e) => format!("the 9th socket's upgrade: {e}"),
    };
    if let Some(conn) = held.pop() {
        conn.close(CLOSE_NORMAL).await;
    }
    let still = held.len();
    let count = match detail_via(ep, target, tok).await {
        Ok(HealthDetailReply { detail: Some(d), .. }) => d.sockets_open.to_string(),
        Ok(r) => format!("? (HTTP {})", r.status),
        Err(e) => format!("? ({e})"),
    };
    for conn in held {
        conn.close(CLOSE_NORMAL).await;
    }
    Ok(format!("{opened} of 8 sockets completed hello and stayed open{short}, then {ninth}; shim sockets_open={count}, read with {still} held sockets open (the 9th and one held socket closed first: with all eight open the endpoint's cap would likely refuse the read)"))
}

// ---- e1 ------------------------------------------------------------------------------------

/// e1's hold on `conn`: an app `ping` every `every` until `hold` has passed,
/// reading everything that comes back; the two measurements of
/// [`probes::verdict_e1`], in whole seconds after `expiry_ms` (the token's
/// expiry, Unix ms). `cut` when the socket closed or a send failed; `silent`
/// when it stayed open but nothing came in for `dead_after` while the pings
/// went out (the shim answers each with a `pong`: an endpoint that stops
/// forwarding without closing looks like this), from its last inbound
/// frame, and when nothing at all came in after the expiry. Only pongs that
/// kept arriving past the expiry leave both `None` (`survives`).
async fn e1_hold(conn: &mut AgentConn, expiry_ms: i64, hold: Duration, every: Duration, dead_after: Duration) -> (Option<i64>, Option<i64>) {
    let after = |at_ms: i64| (at_ms - expiry_ms).div_euclid(1000);
    let now_ms = || i64::try_from(unix_now_ms()).unwrap_or(i64::MAX);
    let activity = conn.activity();
    let last_in_ms = || now_ms() - i64::try_from(activity.idle().as_millis()).unwrap_or(i64::MAX);
    let deadline = tokio::time::Instant::now() + hold;
    let mut ping = tokio::time::interval(every);
    ping.tick().await; // the immediate first tick
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            _ = ping.tick() => {
                if conn.send(&Frame::Ping { ts: unix_now_ms() }).await.is_err() {
                    return (Some(after(now_ms())), None);
                }
                if activity.idle() >= dead_after {
                    return (None, Some(after(last_in_ms())));
                }
            }
            r = conn.recv() => if matches!(r, Ok(None) | Err(_)) {
                return (Some(after(now_ms())), None);
            },
        }
    }
    let last = last_in_ms();
    if last <= expiry_ms {
        return (None, Some(after(last)));
    }
    (None, None)
}

async fn e1<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("e1", 1200, Some(1200), None, true))?;
    let (vm, _row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(s6_fake_refusal("e1"));
    }
    let dial = agent_dial(ctx);
    let wait = hello_wait(ctx);
    // A 2-minute token, held with pings for 4 minutes.
    let token = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 2).await?;
    let expiry_ms = i64::try_from(token.expires_at_unix).unwrap_or(i64::MAX / 1000) * 1000;
    let (mut conn, _ok) = open_hello(&dial, &target, token.value()?, vec![], Some(3600), wait).await?;
    let sid = SpawnId::new_v7();
    conn.send(&Frame::Spawn { spawn_id: sid.clone(), argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(300) }).await?;
    let pid1 = await_spawned(&mut conn, &sid, Duration::from_secs(30)).await?;
    let (cut, silent) = e1_hold(&mut conn, expiry_ms, Duration::from_secs(240), Duration::from_secs(20), crate::wire::frame::DEAD_AFTER).await;
    conn.close(CLOSE_NORMAL).await;
    out.verdict = probes::verdict_e1(cut, silent);
    // WS#2: a fresh token, hello-resume; the pid is unchanged.
    let token2 = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 60).await?;
    let ws2 = open_hello(&dial, &target, token2.value()?, vec![ResumePoint { spawn_id: sid.clone(), from_seq: None, err_from_seq: None }], Some(3600), wait).await;
    let ws2_note = match ws2 {
        Ok((conn2, ok2)) => {
            let status = ok2.resumed.iter().find(|r| r.spawn_id == sid).map(|r| r.status);
            let pid2 = ok2.spawns.iter().find(|s| s.spawn_id == sid).map(|s| s.pid);
            conn2.close(CLOSE_NORMAL).await;
            let same = pid2 == Some(pid1);
            format!("WS#2 hello-resume {status:?}: pid {pid1} → {pid2:?} ({})", if same { "unchanged" } else { "CHANGED" })
        }
        Err(e) => format!("WS#2 hello-resume failed: {e}"),
    };
    out.note = format!("2-min token (expiry +0 s is the cut and silence baseline; silent: no frame for {} s while pinging every 20 s); {ws2_note}", crate::wire::frame::DEAD_AFTER.as_secs());
    Ok(out)
}

// ---- e5 ------------------------------------------------------------------------------------

async fn e5_after<A: MicrovmApi>(api: &A, id: &str, phase: &str, notes: &mut Vec<String>) -> Result<bool, BridgeError> {
    let vm = api.get(id).await?;
    if vm.state.is_terminal() {
        return Err(terminated(&vm));
    }
    let kept = vm.state == VmState::Running;
    notes.push(format!("{phase}: {}", vm.state.as_str()));
    Ok(kept)
}

/// Bring the VM back to RUNNING between phases, timing the resume (the
/// note's auto-resume figure). A suspend still in progress (the shim's
/// `/suspend` closed the phase's socket a moment ago) settles first:
/// ResumeMicrovm answers Conflict until the VM is SUSPENDED.
async fn e5_resume<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str, notes: &mut Vec<String>) -> Result<(), BridgeError> {
    let vm = api.get(id).await?;
    if vm.state == VmState::Running {
        return Ok(());
    }
    if vm.state.is_terminal() {
        return Err(terminated(&vm));
    }
    if vm.state == VmState::Suspending {
        run::wait_for_state(api, id, &VmState::Suspended, run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms)).await?;
    }
    let t = Instant::now();
    match api.resume(id).await {
        Ok(()) | Err(BridgeError::Conflict(_)) => {}
        Err(e) => return Err(e),
    }
    run::wait_for_state(api, id, &VmState::Running, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms)).await?;
    notes.push(format!("resumed in {} ms", t.elapsed().as_millis()));
    Ok(())
}

/// e5: a reconnect to the suspended VM, as a session makes one — once a
/// suspend in progress settled, a fresh token and a timed `/agent` dial
/// with `hello` (with auto-resume the endpoint is expected to resume the VM
/// and hold the request) — what came back, in how long, and the VM's state
/// before and after. Best effort: a failure is the note.
async fn e5_reconnect<A: MicrovmApi>(ctx: &Ctx, api: &A, dial: &AgentDial, target: &AgentTarget, id: &str) -> String {
    let run = async {
        let mut before = api.get(id).await?.state;
        if before == VmState::Suspending {
            before = run::wait_for_state(api, id, &VmState::Suspended, run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms)).await?.state;
        }
        let tok = token::mint(api, &ctx.paths, id, APP_PORT, 60).await?;
        let t = Instant::now();
        let r = open_hello(dial, target, tok.value()?, vec![], Some(3600), hello_wait(ctx)).await;
        let ms = t.elapsed().as_millis();
        let said = match r {
            Ok((conn, _)) => {
                conn.close(CLOSE_NORMAL).await;
                "hello_ok".to_string()
            }
            Err(e) => e.to_string(),
        };
        let after = api.get(id).await.map_or_else(|e| format!("unknown ({e})"), |v| v.state.as_str().to_string());
        Ok::<_, BridgeError>(format!("reconnect to the {} VM: {said} after {ms} ms, then {after}", before.as_str()))
    };
    run.await.unwrap_or_else(|e: BridgeError| format!("reconnect to the suspended VM not measured: {e}"))
}

/// e5's fourth phase: no socket, a bearer-less `GET /health` every `every`
/// for `phase`, and `GetMicrovm` after each GET and every `poll` between
/// them. A GET to a suspended VM resumes it (auto-resume), so one read at
/// the end can land in a RUNNING window after a suspension: the phase kept
/// the VM up only when every read that answered said RUNNING. A poll that
/// fails (an error that outlived the SDK's retries) is counted for the note,
/// with the last error, and the polling goes on: one such error must not
/// end the 15–20 min e5. An error of the phase's final state read still
/// ends it, as does a VM that is gone at any read (a terminal state, or
/// `ResourceNotFound`: final, as in `run::wait_for_state`). Returns whether
/// the phase kept the VM up, and the note.
async fn e5_http_phase<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, target: &AgentTarget, tok: &AuthToken, phase: Duration, every: Duration, poll: Duration) -> Result<(bool, String), BridgeError> {
    let t0 = Instant::now();
    let (mut polls, mut left, mut last) = (0u32, None::<String>, String::new());
    let (mut failed, mut error) = (0u32, String::new());
    let mut seen = |vm: VmInfo| {
        if vm.state.is_terminal() {
            return Err(terminated(&vm));
        }
        polls += 1;
        if left.is_none() && vm.state != VmState::Running {
            left = Some(format!("{} at +{} s", vm.state.as_str(), t0.elapsed().as_secs()));
        }
        last = vm.state.as_str().to_string();
        Ok(())
    };
    let mut next_get = t0;
    while t0.elapsed() < phase {
        if Instant::now() >= next_get {
            let _ = ep.get_health(&target.endpoint, tok, APP_PORT).await;
            next_get += every;
        }
        match api.get(&target.vm_id).await {
            Ok(vm) => seen(vm)?,
            Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
            Err(e) => {
                failed += 1;
                error = e.to_string();
            }
        }
        tokio::time::sleep(poll.min(next_get.saturating_duration_since(Instant::now()))).await;
    }
    // The phase's final state read: an error here ends the probe, as e5_after's does.
    seen(api.get(&target.vm_id).await?)?;
    let failures = if failed == 0 { String::new() } else { format!(" ({failed} more failed, the last: {error})") };
    Ok(match left {
        None => (true, format!("http: RUNNING at all {polls} polls{failures}")),
        Some(s) => (false, format!("http: {s} (a GET resumes a suspended VM), {last} at the end of {polls} polls{failures}")),
    })
}

async fn e5<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("e5", 2400, Some(60), Some(1500), true))?;
    let (vm, _row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(s6_fake_refusal("e5"));
    }
    let dial = agent_dial(ctx);
    let wait = hello_wait(ctx);
    let phase = Duration::from_secs(180);
    let mut notes = Vec::new();

    // Phase 1: a silent socket with a sleep spawn; no pings, no acks.
    {
        let tok = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 60).await?;
        let (mut conn, _) = open_hello(&dial, &target, tok.value()?, vec![], Some(3600), wait).await?;
        let sid = SpawnId::new_v7();
        conn.send(&Frame::Spawn { spawn_id: sid.clone(), argv: vec!["sleep".into(), "3600".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(60) }).await?;
        let _ = await_spawned(&mut conn, &sid, Duration::from_secs(30)).await;
        tokio::time::sleep(phase).await;
        drop(conn);
    }
    let silent = e5_after(api, &vm.id, "silent", &mut notes).await?;
    // The reconnect to a suspended VM: measured after the first phase that left the VM suspended.
    let mut reconnected = false;
    if !silent {
        notes.push(e5_reconnect(ctx, api, &dial, &target, &vm.id).await);
        reconnected = true;
    }
    e5_resume(ctx, api, &vm.id, &mut notes).await?;

    // Phase 2: app pings every 20 s, nothing else.
    {
        let tok = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 60).await?;
        let (mut conn, _) = open_hello(&dial, &target, tok.value()?, vec![], Some(3600), wait).await?;
        let until = Instant::now() + phase;
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        while Instant::now() < until {
            tokio::select! {
                _ = ping.tick() => { let _ = conn.send(&Frame::Ping { ts: crate::wire::time::unix_now_ms() }).await; }
                r = conn.recv() => if matches!(r, Ok(None) | Err(_)) { break; }
            }
        }
        drop(conn);
    }
    let pings = e5_after(api, &vm.id, "pings", &mut notes).await?;
    if !pings && !reconnected {
        notes.push(e5_reconnect(ctx, api, &dial, &target, &vm.id).await);
        reconnected = true;
    }
    e5_resume(ctx, api, &vm.id, &mut notes).await?;

    // Phase 3: VM→Mac output only (a line every 10 s); no pings, no acks.
    {
        let tok = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 60).await?;
        let (mut conn, _) = open_hello(&dial, &target, tok.value()?, vec![], Some(3600), wait).await?;
        let sid = SpawnId::new_v7();
        conn.send(&Frame::Spawn { spawn_id: sid.clone(), argv: vec!["sh".into(), "-c".into(), "while true; do echo tick; sleep 10; done".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(60) }).await?;
        let until = Instant::now() + phase;
        while Instant::now() < until {
            // Drain VM→Mac frames without acking; a closed socket (suspend) ends the drain.
            match tokio::time::timeout(Duration::from_secs(5), conn.recv()).await {
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) | Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
        drop(conn);
    }
    let outbound = e5_after(api, &vm.id, "outbound", &mut notes).await?;
    if !outbound && !reconnected {
        notes.push(e5_reconnect(ctx, api, &dial, &target, &vm.id).await);
        reconnected = true;
    }
    e5_resume(ctx, api, &vm.id, &mut notes).await?;
    if !reconnected {
        notes.push("no socket phase left the VM suspended: no reconnect to a suspended VM measured".to_string());
    }

    // Phase 4: no socket, a bearer-less GET /health every 30 s; GetMicrovm every 5 s.
    let tok = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 60).await?;
    let (http, http_note) = e5_http_phase(api, ep, &target, &tok, phase, Duration::from_secs(30), Duration::from_secs(5)).await?;
    notes.push(http_note);

    out.verdict = probes::verdict_e5(silent, pings, outbound, http);
    notes.push("whether 8080 traffic reached the shim before /resume returned could not be measured from the Mac (the endpoint holds the request through /resume)".to_string());
    out.note = notes.join("; ");
    Ok(out)
}

// ---- frames --------------------------------------------------------------------------------

/// 1 000 lines (one of 1 MiB), a 20 MiB line, non-UTF-8 bytes and an
/// unterminated last line — what `cat` must echo back byte-for-byte.
fn frames_input() -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..1000u32 {
        if i == 500 {
            v.extend(std::iter::repeat_n(b'A', 1024 * 1024));
        } else {
            v.extend_from_slice(format!("line-{i}").as_bytes());
        }
        v.push(b'\n');
    }
    v.extend(std::iter::repeat_n(b'B', 20 * 1024 * 1024));
    v.push(b'\n');
    v.extend_from_slice(&[0x00, 0xff, 0xfe, 0x80, 0x01]);
    v.push(b'\n');
    v.extend_from_slice("tail without a newline \u{20ac}".as_bytes());
    v
}

async fn frames<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("frames", 900, None, None, true))?;
    let (_vm, row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(s6_fake_refusal("frames"));
    }
    let policy = RunPolicy::from_cfg(&ctx.cfg.transport, &row, ctx.knobs.backoff_ms);
    let env = AgentEnv { api, ep, paths: &ctx.paths, target, policy, dial: agent_dial(ctx) };
    let input = frames_input();
    let spec = SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60) };
    let t = Instant::now();
    let (stdout, stderr, _pid, exit) = exec_agent(&env, spec, input.clone()).await?;
    let secs = t.elapsed().as_secs_f64().max(0.001);
    let mib = input.len() as f64 / (1024.0 * 1024.0);
    out.verdict = probes::verdict_frames(&input, &stdout);
    out.note = format!("{} bytes each way in {:.1} s ({:.1} MB/s round trip); exit code={:?} signal={:?}; stderr {} bytes", input.len(), secs, mib * 2.0 / secs, exit.code, exit.signal, stderr.len());
    Ok(out)
}

// ---- reattach ------------------------------------------------------------------------------

/// 20 000 lines `line-0` … `line-19999` over about 5 s (a 0.05 s pause every
/// 200 lines), then exit 0. It must outlive the cut after the first chunk
/// plus the D22 ladder (TERM at +0.8 s, KILL at +1.2 s) by a wide margin:
/// a producer that is done before the ladder could fire cannot show that a
/// lost socket killed it (critic H1).
const REATTACH_PRODUCER: &str = "i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); if [ $((i % 200)) -eq 0 ]; then sleep 0.05; fi; done";

async fn reattach<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("reattach", 900, None, None, true))?;
    let (vm, row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(s6_fake_refusal("reattach"));
    }
    let dial = agent_dial(ctx);
    let policy = RunPolicy::from_cfg(&ctx.cfg.transport, &row, ctx.knobs.backoff_ms);
    let env = AgentEnv { api, ep, paths: &ctx.paths, target: target.clone(), policy, dial };

    // Session 1: a producer with a null stdin, cut client-side after the first chunk.
    let producer = SpawnSpec { argv: vec!["sh".into(), "-c".into(), REATTACH_PRODUCER.into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(300) };
    let (io1, c1) = spawn_channels(16);
    drop(c1.input); // null stdin → EOF
    let mut ev1 = c1.events;
    let consumed1 = c1.consumed.clone();
    let mut out_bytes = Vec::new();
    let (mut last_seq, mut sid, mut pid1, mut chunks) = (0u64, None::<SpawnId>, None::<u32>, 0u32);
    let mut session1 = Box::pin(run_spawn(&env, Start::New(producer), io1));
    let finished_early = loop {
        tokio::select! {
            ev = ev1.recv() => match ev {
                Some(SpawnEvent::Started { spawn_id, pid, .. }) => { sid = Some(spawn_id); pid1 = Some(pid); }
                Some(SpawnEvent::Stdout { seq, bytes }) => {
                    out_bytes.extend_from_slice(&bytes);
                    last_seq = seq;
                    consumed1.stdout_done(seq);
                    chunks += 1;
                    if chunks >= 1 && sid.is_some() { break false; }
                }
                Some(_) => {}
                None => break true,
            },
            r = &mut session1 => { r?; break true; }
        }
    };
    drop(session1); // the client-side cut: the socket closes

    let sid = sid.ok_or_else(|| BridgeError::Protocol("reattach: the producer sent no spawned frame".into()))?;

    // Session 2: reattach from last+1 and collect the rest.
    let reattach_at = Instant::now();
    let (io2, c2) = spawn_channels(16);
    drop(c2.input);
    let mut ev2 = c2.events;
    let consumed2 = c2.consumed.clone();
    let mut pid2 = None;
    let mut session2 = Box::pin(run_spawn(&env, Start::Attach { spawn_id: sid.clone(), from_seq: Some(last_seq + 1), err_from_seq: None }, io2));
    let outcome2 = loop {
        tokio::select! {
            ev = ev2.recv() => match ev {
                Some(SpawnEvent::Started { pid, .. }) => pid2 = Some(pid),
                Some(SpawnEvent::Stdout { seq, bytes }) => { out_bytes.extend_from_slice(&bytes); consumed2.stdout_done(seq); }
                Some(_) => {}
                None => {}
            },
            r = &mut session2 => break r,
        }
    };
    while let Ok(ev) = ev2.try_recv() {
        if let SpawnEvent::Stdout { bytes, .. } = ev {
            out_bytes.extend_from_slice(&bytes);
        }
    }
    let outcome2 = outcome2?;
    let reattach_ms = reattach_at.elapsed().as_millis();

    // No line lost or doubled, and the same pid.
    let mut seen = vec![0u32; 20000];
    let mut malformed = 0u64;
    for line in String::from_utf8_lossy(&out_bytes).lines() {
        match line.strip_prefix("line-").and_then(|n| n.parse::<usize>().ok()) {
            Some(n) if n < 20000 => seen[n] += 1,
            _ if line.is_empty() => {}
            _ => malformed += 1,
        }
    }
    let missing = seen.iter().filter(|c| **c == 0).count() as u64;
    let doubled = seen.iter().filter(|c| **c > 1).count() as u64;
    let same_pid = pid1.is_some() && pid1 == pid2;
    out.verdict = probes::verdict_reattach(missing, doubled, same_pid, outcome2.exit.code, outcome2.exit.signal);

    let mut notes = vec![format!(
        "cut after {chunks} chunk(s){}; reattached from seq {} in {reattach_ms} ms; pid {pid1:?} → {pid2:?}; {malformed} malformed lines; exit code={:?} signal={:?}",
        if finished_early { " (the producer finished first; the reattach collected the retained tail)" } else { "" },
        last_seq + 1,
        outcome2.exit.code,
        outcome2.exit.signal,
    )];
    notes.push(reattach_gap(ctx, api, &dial, &target, &vm.id).await);
    notes.push(reattach_window_kill(ctx, api, &dial, &target, &vm.id).await);
    out.note = notes.join("; ");
    Ok(out)
}

/// A stale `from_seq` after acks must answer `gap` (best effort; the note).
async fn reattach_gap<A: MicrovmApi>(ctx: &Ctx, api: &A, dial: &AgentDial, target: &AgentTarget, id: &str) -> String {
    let wait = hello_wait(ctx);
    let run = async {
        let tok = token::mint(api, &ctx.paths, id, APP_PORT, 5).await?;
        let (mut conn, _) = open_hello(dial, target, tok.value()?, vec![], Some(3600), wait).await?;
        let gsid = SpawnId::new_v7();
        conn.send(&Frame::Spawn { spawn_id: gsid.clone(), argv: vec!["sh".into(), "-c".into(), "i=0; while [ $i -lt 200000 ]; do echo g-$i; i=$((i+1)); done; sleep 120".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(60) }).await?;
        await_spawned(&mut conn, &gsid, Duration::from_secs(30)).await?;
        // Ack up to a high seq so the shim trims past seq 1, until the output quiets.
        let mut hi = 0u64;
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(5), conn.recv()).await {
                Ok(Ok(Some(Frame::Stdout { seq, .. }))) => {
                    hi = seq;
                    conn.send(&Frame::Ack { spawn_id: gsid.clone(), seq, err_seq: 0 }).await?;
                }
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) | Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
        let tok2 = token::mint(api, &ctx.paths, id, APP_PORT, 5).await?;
        let mut c2 = AgentConn::open(dial, &target.endpoint, tok2.value()?).await.map_err(|e| BridgeError::Endpoint(format!("gap dial: {e}")))?;
        let ok = hello_bounded(&mut c2, target, vec![ResumePoint { spawn_id: gsid.clone(), from_seq: Some(1), err_from_seq: None }], Some(3600), wait).await?;
        let status = ok.resumed.iter().find(|r| r.spawn_id == gsid).map(|r| r.status);
        c2.send(&Frame::Signal { spawn_id: gsid, sig: Sig::Kill, scope: Scope::Group }).await.ok();
        c2.close(CLOSE_NORMAL).await;
        drop(conn);
        Ok::<_, BridgeError>(match status {
            Some(ResumeStatus::Gap) => format!("stale from_seq 1 after acking to {hi}: gap"),
            other => format!("stale from_seq 1 after acking to {hi}: {other:?} (expected gap)"),
        })
    };
    run.await.unwrap_or_else(|e: BridgeError| format!("gap case not reproduced: {e}"))
}

/// A full stdout window, a kill -9, then an attach must replay and exit 137 (best effort; the note).
async fn reattach_window_kill<A: MicrovmApi>(ctx: &Ctx, api: &A, dial: &AgentDial, target: &AgentTarget, id: &str) -> String {
    let wait = hello_wait(ctx);
    let run = async {
        let tok = token::mint(api, &ctx.paths, id, APP_PORT, 5).await?;
        let (mut conn, _) = open_hello(dial, target, tok.value()?, vec![], Some(3600), wait).await?;
        let wsid = SpawnId::new_v7();
        conn.send(&Frame::Spawn { spawn_id: wsid.clone(), argv: vec!["sh".into(), "-c".into(), "head -c 20000000 /dev/zero | tr '\\0' X".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(60) }).await?;
        await_spawned(&mut conn, &wsid, Duration::from_secs(30)).await?;
        // Read up to the window WITHOUT acking so it fills and the shim stops reading the child.
        let mut got = 0u64;
        let deadline = Instant::now() + Duration::from_secs(30);
        while got < crate::wire::frame::STDOUT_WINDOW_BYTES && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(5), conn.recv()).await {
                Ok(Ok(Some(Frame::Stdout { data, .. }))) => got += crate::wire::chunk::raw_len(&data).unwrap_or(0) as u64,
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) | Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
        conn.send(&Frame::Signal { spawn_id: wsid.clone(), sig: Sig::Kill, scope: Scope::Group }).await?;
        drop(conn);
        // Attach from seq 1: replay, then the exit.
        let tok2 = token::mint(api, &ctx.paths, id, APP_PORT, 5).await?;
        let mut c2 = AgentConn::open(dial, &target.endpoint, tok2.value()?).await.map_err(|e| BridgeError::Endpoint(format!("window dial: {e}")))?;
        let ok = hello_bounded(&mut c2, target, vec![ResumePoint { spawn_id: wsid.clone(), from_seq: Some(1), err_from_seq: None }], Some(3600), wait).await?;
        let status = ok.resumed.iter().find(|r| r.spawn_id == wsid).map(|r| r.status);
        let (mut replayed, mut signal) = (0u64, None);
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(10), c2.recv()).await {
                Ok(Ok(Some(Frame::Stdout { seq, data, .. }))) => {
                    replayed += crate::wire::chunk::raw_len(&data).unwrap_or(0) as u64;
                    c2.send(&Frame::Ack { spawn_id: wsid.clone(), seq, err_seq: 0 }).await?;
                }
                Ok(Ok(Some(Frame::Exit { signal: s, .. }))) => {
                    signal = s;
                    break;
                }
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) | Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
        c2.close(CLOSE_NORMAL).await;
        Ok::<_, BridgeError>(format!("full window ({got} bytes) + kill -9, attach {status:?}: replayed {replayed} bytes, exit signal {signal:?} (status {:?})", signal.map(|s| 128 + s)))
    };
    run.await.unwrap_or_else(|e: BridgeError| format!("window+kill case not reproduced: {e}"))
}

// ---- clock-after-resume --------------------------------------------------------------------

fn unix_f64(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

async fn clock_after_resume<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    let mut f = flags("clock-after-resume", 2400, None, Some(1500), true);
    f.egress = Some(run::Egress::Vpc);
    let p = plan(ctx, &f)?;
    let (vm, row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(s6_fake_refusal("clock-after-resume"));
    }
    let dial = agent_dial(ctx);
    // Suspend, hold suspended at least 15 min, resume.
    api.suspend(&vm.id).await?;
    run::wait_for_state(api, &vm.id, &VmState::Suspended, run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms)).await?;
    let hold = ctx.knobs.backoff_ms.map_or(Duration::from_secs(15 * 60), |ms| Duration::from_millis(ms.saturating_mul(900)));
    let held = Instant::now();
    while held.elapsed() < hold {
        tokio::time::sleep((hold - held.elapsed()).min(Duration::from_secs(30))).await;
        let vm = api.get(&vm.id).await?;
        if vm.state.is_terminal() {
            return Err(terminated(&vm));
        }
    }
    api.resume(&vm.id).await?;
    run::wait_for_state(api, &vm.id, &VmState::Running, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms)).await?;

    // The first proxied success after resume (curl through the proxy env until 401/200).
    let policy = RunPolicy::from_cfg(&ctx.cfg.transport, &row, ctx.knobs.backoff_ms);
    let proxy_env: BTreeMap<String, String> = egress::proxy_env(&egress::check::proxy_ip(&ctx.cfg, &ctx.paths), egress::PROXY_PORT).into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let env = AgentEnv { api, ep, paths: &ctx.paths, target: target.clone(), policy, dial };
    let curl = "s=$SECONDS; code=000; while [ $((SECONDS-s)) -lt 120 ]; do code=$(command curl -sS -o /dev/null -w '%{http_code}' -m 5 https://api.anthropic.com/v1/models 2>/dev/null); case $code in 401|200) break;; esac; command sleep 2; done; echo \"proxy code=$code after=$((SECONDS-s))s\"";
    let proxy_note = match exec_agent(&env, SpawnSpec { argv: vec!["bash".into(), "-c".into(), curl.into()], cwd: None, env: proxy_env, detach_grace_s: Some(60) }, Vec::new()).await {
        Ok((o, _, _, _)) => String::from_utf8_lossy(&o).trim().to_string(),
        Err(e) => format!("first proxied success not measured: {e}"),
    };

    // The guest clock against the Mac, on one open socket (round-trip corrected).
    let tok = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 10).await?;
    let (mut conn, _) = open_hello(&dial, &target, tok.value()?, vec![], Some(3600), hello_wait(ctx)).await?;
    let (date_out, t0, t1) = conn_exec(&mut conn, &["date", "-u", "+%s.%N"], Duration::from_secs(30)).await?;
    conn.close(CLOSE_NORMAL).await;
    let guest = date_out.trim().parse::<f64>().ok();
    let mac_mid = (unix_f64(t0) + unix_f64(t1)) / 2.0;
    let offset = guest.map(|g| g - mac_mid);
    out.verdict = offset.map_or_else(|| "no-clock".to_string(), probes::verdict_clock);

    // The monotonic/boottime deltas from the /health/detail clock report, against wall time.
    let detail = detail_via(ep, &target, &tok).await.ok().and_then(|d| d.detail);
    let clock_note = detail.and_then(|d| d.clock).map_or_else(|| "no clock report in /health/detail".to_string(), |c| format!("clock report: {c}"));
    out.note = format!("guest-Mac offset {}; {proxy_note}; {clock_note}", offset.map_or("?".to_string(), |o| format!("{o:.3} s")));
    Ok(out)
}

/// Spawn `argv` on an open socket and time the first stdout (round-trip
/// bracket t0..t1): the stdout text and both instants.
async fn conn_exec(conn: &mut AgentConn, argv: &[&str], budget: Duration) -> Result<(String, SystemTime, SystemTime), BridgeError> {
    let sid = SpawnId::new_v7();
    let spec = Frame::Spawn { spawn_id: sid.clone(), argv: argv.iter().map(|s| (*s).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(30) };
    let t0 = SystemTime::now();
    conn.send(&spec).await?;
    let (mut out, mut t1, mut got) = (String::new(), t0, false);
    let deadline = Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, conn.recv()).await {
            Ok(Ok(Some(Frame::Stdout { seq, data, .. }))) => {
                if !got {
                    t1 = SystemTime::now();
                    got = true;
                }
                out.push_str(&String::from_utf8_lossy(&crate::wire::chunk::decode(&data).unwrap_or_default()));
                conn.send(&Frame::Ack { spawn_id: sid.clone(), seq, err_seq: 0 }).await?;
            }
            Ok(Ok(Some(Frame::Exit { .. }))) => break,
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) | Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    Ok((out, t0, t1))
}

// ---- in-vm-firewall ------------------------------------------------------------------------

/// The start of both in-vm-firewall agent scripts: `hc` (one request's HTTP
/// status, `000` when nothing answered) and `V`, the VM's own IPv4 address
/// from `/proc/net/fib_trie` (the image has no `ip`; empty when not found),
/// named by `@@vmip`.
const FIREWALL_COMMON: &str = r#"set +e
hc() { command curl -sS -o /dev/null -w '%{http_code}' -m 5 "$@" 2>/dev/null || echo 000; }
V=$(awk '/\|-- /{ip=$2} /32 host LOCAL/{print ip}' /proc/net/fib_trie 2>/dev/null | grep -vx '127.0.0.1' | head -1)
echo "@@vmip ${V:-none}"
"#;

/// The default VM's checks (markers prefixed `@@`): the benign forged hooks
/// first (`/resume` via loopback and the VM's own address, so an admission
/// shows up as a marker), 8080 (the public `GET /health` and the bearer's
/// `GET /health/detail`) and 9418 locally, NoNewPrivs, the setuid inventory,
/// IMDS computed in the VM (never the credential JSON), nf_tables symbol
/// counts.
const FIREWALL_CHECKS: &str = r#"P=/aws/lambda-microvms/runtime/v1
echo "@@hook-resume-lo $(hc -X POST http://127.0.0.1:9000$P/resume)"
if [ -n "$V" ]; then
  echo "@@hook-resume-self $(hc -X POST http://$V:9000$P/resume)"
fi
echo "@@local-8080 $(hc http://127.0.0.1:8080/health)"
echo "@@detail-8080 $(hc http://127.0.0.1:8080/health/detail)"
echo "@@local-9418 $(hc http://127.0.0.1:9418/)"
echo "@@nnp $(grep -i NoNewPrivs /proc/self/status 2>/dev/null | awk '{print $2}')"
echo "@@setuid-begin"
find / -xdev -perm -4000 -type f 2>/dev/null
echo "@@setuid-end"
I=http://169.254.169.254
T=$(command curl -sS -m 3 -X PUT "$I/latest/api/token" -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)
TS=$([ -n "$T" ] && echo ok || echo none)
R=$(command curl -sS -m 3 -H "X-aws-ec2-metadata-token: $T" "$I/latest/meta-data/iam/security-credentials/" 2>/dev/null)
CS=$([ -n "$R" ] && echo present || echo none)
KEYS=no
if [ -n "$R" ]; then
  C=$(command curl -sS -m 3 -H "X-aws-ec2-metadata-token: $T" "$I/latest/meta-data/iam/security-credentials/$(printf %s "$R" | head -1)" 2>/dev/null)
  printf %s "$C" | grep -q AccessKeyId && KEYS=yes
fi
echo "@@imds token:$TS creds:$CS keys:$KEYS"
echo "@@nft $(grep -cE 'nft_|nf_tables|xt_owner' /proc/kallsyms 2>/dev/null || echo 0)"
"#;

/// Every foreign listener, passed as `<addr> <port>` argument pairs, dialed
/// from uid 1000 where it listens — a wildcard at loopback and at the VM's
/// own address (`0.0.0.0`: 127.0.0.1 and `$V`; `::`: ::1, 127.0.0.1 and
/// `$V`), any other address as given — over TCP, then HTTP: one `@@foreign
/// <addr> <port> <dialed> <connect|refused> http:<code>` line per dial. A
/// listener that cannot be dialed everywhere it listens gets `@@foreign
/// <addr> <port> <what is missing> undialed`: a wildcard while `$V` is
/// empty (`vm-address`), an IPv6 link-local address (`no-scope`: its
/// interface is not in `/proc/net/tcp6`).
const FIREWALL_FOREIGN: &str = r#"while [ $# -ge 2 ]; do
  a=$1 p=$2
  shift 2
  case $a in 0.0.0.0) t="127.0.0.1 $V" ;; ::) t="::1 127.0.0.1 $V" ;; fe[89ab]?:*) t= ;; *) t=$a ;; esac
  for h in $t; do
    if timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then r=connect; else r=refused; fi
    case $h in *:*) u="[$h]" ;; *) u=$h ;; esac
    echo "@@foreign $a $p $h $r http:$(hc -g "http://$u:$p/")"
  done
  case $a in 0.0.0.0 | ::) [ -n "$V" ] || echo "@@foreign $a $p vm-address undialed" ;; fe[89ab]?:*) echo "@@foreign $a $p no-scope undialed" ;; esac
done
"#;

/// The default VM's forged terminate hooks, last: one the guard admits
/// drains the VM and ends this script ([`drained_by_forged_hook`]). Via
/// loopback and the VM's own address, then the close-before-lookup trick.
const FIREWALL_TERMINATE: &str = r#"echo "@@hook-term-lo $(hc -X POST http://127.0.0.1:9000$P/terminate)"
if [ -n "$V" ]; then
  echo "@@hook-term-self $(hc -X POST http://$V:9000$P/terminate)"
fi
# Close-before-lookup (critic M6a): a uid-1000 client that sends a full
# /terminate and closes at once leaves no /proc/net/tcp row, so only the
# orphan/inode-0 rule refuses it. A single shot usually loses the race (the
# socket is still enumerable when the guard looks), so loop to hit it.
o=0
while [ $o -lt 20 ]; do
  ( exec 3<>/dev/tcp/127.0.0.1/9000 && printf 'POST %s/terminate HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n' "$P" >&3 ) 2>/dev/null
  o=$((o+1))
done
echo "@@orphan sent"
echo "@@done"
"#;

/// The agent script the default VM runs: the checks, every foreign listener
/// (its arguments), and the forged terminate hooks last.
fn firewall_agent_script() -> String {
    [FIREWALL_COMMON, FIREWALL_CHECKS, FIREWALL_FOREIGN, FIREWALL_TERMINATE].concat()
}

/// The default VM's RST abort (critic M6a's snapshot case live; T6.6's
/// `l1_an_rst_aborted_agent_request_is_refused` in Docker): five uid-1000
/// connections to 8080 through the VM's own address `$V`, which exists only
/// once the snapshot is restored. Each sends `GET /health` and leaves the
/// answer unread, then a second `GET /health` in ONE write by `dd`, the
/// socket's only holder, whose exit resets the connection at once (a close
/// with data unread). The shim still reads and dispatches the queued
/// request and, finding no row for a local address, must refuse it
/// `no_row`: a guard that took its addresses before the snapshot would see
/// `$V` as remote and admit it. bash's own `printf` writes line by line, so
/// the reset would discard a tail Nagle held. `@@rst-8080 <connections
/// made>`; nothing without `$V`.
const FIREWALL_RST: &str = r#"if [ -n "$V" ]; then
  n=0
  for i in 1 2 3 4 5; do
    # The here-string adds the head's last \n.
    ( exec 3<>"/dev/tcp/$V/8080" || exit 1; printf 'GET /health HTTP/1.1\r\nHost: vm\r\n\r\n' >&3; sleep 0.3; printf -v req 'GET /health HTTP/1.1\r\nHost: vm\r\n\r'; exec dd bs=4096 status=none <<<"$req" >&3 3>&- ) 2>/dev/null && n=$((n+1))
  done
  echo "@@rst-8080 $n"
fi
echo "@@done"
"#;

/// The default VM's first agent script, run alone between two reads of the
/// guard's refusal count: the RST abort ([`FIREWALL_RST`]).
fn firewall_rst_script() -> String {
    [FIREWALL_COMMON, FIREWALL_RST].concat()
}

/// The `--shell` VM's agent part: can uid 1000 reach the platform shell's
/// 8022 — at 127.0.0.1, ::1 and the VM's own address — over TCP, and with a
/// WebSocket upgrade over HTTP? One `@@shell8022 <dialed> <connect|refused>
/// http:<code>` line per address.
const FIREWALL_SHELL_8022: &str = r#"for h in 127.0.0.1 ::1 $V; do
  if timeout 4 bash -c "exec 3<>/dev/tcp/$h/8022" 2>/dev/null; then r=connect; else r=refused; fi
  case $h in *:*) u="[$h]" ;; *) u=$h ;; esac
  echo "@@shell8022 $h $r http:$(hc -g -H 'Connection: Upgrade' -H 'Upgrade: websocket' "http://$u:8022/")"
done
echo "@@done"
"#;

/// The agent script the `--shell` VM runs.
fn firewall_shell_script() -> String {
    [FIREWALL_COMMON, FIREWALL_SHELL_8022].concat()
}

/// The `--shell` VM's platform-shell script (root, through
/// `vm::shell::run_script`): its uid and every LISTEN row of
/// `/proc/net/tcp` and `tcp6` (local address, uid, inode), each on a marker
/// line of this run (`@@AIENV<nonce> uid|listen …`, built at run time, so
/// the shell's echo of the script never holds one), then `end` and `exit`.
fn platform_shell_script(nonce: &str) -> String {
    format!(
        r#"\unalias -a; unset -f command printf id awk 2>/dev/null; hash -r; unset HISTFILE; set +H
R=AIENV{nonce}
printf '%s%s uid %s\n' '@@' "$R" "$(id -u)"; for f in /proc/net/tcp /proc/net/tcp6; do awk -v m="@@$R" 'FNR > 1 && $4 == "0A" {{ print m, "listen", $2, $8, $10 }}' "$f" 2>/dev/null; done; printf '%s%s end\n' '@@' "$R"
exit
"#
    )
}

/// One `@@key value` marker's value, if present.
fn marker<'a>(out: &'a str, key: &str) -> Option<&'a str> {
    out.lines().find_map(|l| l.trim().strip_prefix("@@")?.strip_prefix(key)?.strip_prefix(' ').or(Some("")))
}

/// Every `@@key value` marker's value for `key`.
fn markers<'a>(out: &'a str, key: &str) -> Vec<&'a str> {
    out.lines().filter_map(|l| l.trim().strip_prefix("@@")?.strip_prefix(key)?.strip_prefix(' ').or(Some(""))).collect()
}

/// The `--shell` VM's flags for in-vm-firewall: like the default VM (the
/// brief gives no egress qualifier, so the default egress applies), plus
/// `--shell` for the SHELL_INGRESS ingress. The shell token needs
/// SHELL_INGRESS, not a vpc egress connector, so forcing `vpc` here only
/// coupled the whole `--shell` measurement to a connector being configured
/// (`plan` errors `EgressRequired` without one, skipping the 8022/id-u/LISTEN
/// checks) for no reason.
fn firewall_shell_flags() -> run::RunFlags {
    let mut sf = flags("in-vm-firewall", 900, None, None, true);
    sf.shell = true;
    sf
}

/// Name the gap `name`, once.
fn gap(gaps: &mut Vec<&'static str>, name: &'static str) {
    if !gaps.contains(&name) {
        gaps.push(name);
    }
}

/// `addr:port`, `[addr]:port` for IPv6.
fn socket(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

/// `/health/detail`'s listener inventory (`addr:port uid <n> inode <n>`,
/// `own` for the shim's) and the last admitted peer of each runtime hook —
/// the platform's hook client: family, uid, inode — for the note.
fn inventory(d: &HealthDetail) -> String {
    let n = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
    let listeners: Vec<String> = d.listeners.iter().map(|l| format!("{} uid {} inode {}{}", socket(&l.addr, l.port), l.uid, l.inode, if l.own { " own" } else { "" })).collect();
    let peers: Vec<String> = d.hook_peers.iter().map(|(hook, p)| format!("{hook} {} fam {} uid {} inode {} {}", p.peer, n(p.family.map(u64::from)), n(p.uid.map(u64::from)), n(p.inode), p.decision)).collect();
    let listed = |l: Vec<String>| if l.is_empty() { "none".to_string() } else { l.join(", ") };
    format!("listeners: {}; hook peers: {}", listed(listeners), listed(peers))
}

/// The listeners in-vm-firewall dials from uid 1000: every one
/// `/health/detail` lists that the shim does not own, with the address it
/// listens on; the note gets the whole [`inventory`]. A detail that could
/// not be read, or that left listeners out, is a `listeners` gap: the
/// verdict must not read `guarded` when not every foreign listener was tried.
fn foreign_listeners(reply: Result<HealthDetailReply, BridgeError>, notes: &mut Vec<String>, gaps: &mut Vec<&'static str>) -> Vec<(String, u16)> {
    match reply {
        Ok(HealthDetailReply { detail: Some(d), .. }) => {
            notes.push(inventory(&d));
            if d.listeners_omitted > 0 {
                notes.push(format!("/health/detail left {} listeners out", d.listeners_omitted));
                gap(gaps, "listeners");
            }
            d.listeners.iter().filter(|l| !l.own).map(|l| (l.addr.clone(), l.port)).collect()
        }
        Ok(r) => {
            notes.push(format!("/health/detail answered {} without a detail", r.status));
            gap(gaps, "listeners");
            Vec::new()
        }
        Err(e) => {
            notes.push(format!("/health/detail failed: {e}"));
            gap(gaps, "listeners");
            Vec::new()
        }
    }
}

/// The foreign listeners' dials in `text` ([`FIREWALL_FOREIGN`]): a dial that
/// connected exposes the listener's port; one not dialed everywhere it
/// listens (no line for it, or `undialed`) is a `listeners` gap. The note
/// names each listener's address and every dial.
fn judge_foreign(text: &str, foreign: &[(String, u16)], notes: &mut Vec<String>, exposures: &mut Vec<u16>, gaps: &mut Vec<&'static str>) {
    let lines: Vec<Vec<&str>> = markers(text, "foreign").into_iter().map(|l| l.split_whitespace().collect()).collect();
    for (addr, port) in foreign {
        let port_text = port.to_string();
        let dials: Vec<&Vec<&str>> = lines.iter().filter(|w| w.len() >= 4 && w[0] == addr && w[1] == port_text).collect();
        if dials.is_empty() || dials.iter().any(|w| w[3] == "undialed") {
            gap(gaps, "listeners");
        }
        if dials.iter().any(|w| w[3] == "connect") {
            exposures.push(*port);
        }
        let said = if dials.is_empty() { "not dialed".to_string() } else { dials.iter().map(|w| w[2..].join(" ")).collect::<Vec<_>>().join(", ") };
        notes.push(format!("foreign listener {}: {said}", socket(addr, *port)));
    }
}

/// `/health/detail`'s `agent_guard` (`on`, `log` or `off`), when it was read.
fn guard_mode(reply: &Result<HealthDetailReply, BridgeError>) -> Option<String> {
    reply.as_ref().ok()?.detail.as_ref().map(|d| d.agent_guard.clone())
}

/// The guard's 8080 refusal count in a `/health/detail` reply
/// (`refused_peers`, none yet being 0), or why the reply has none.
fn refused_8080(reply: &Result<HealthDetailReply, BridgeError>) -> Result<u64, String> {
    match reply {
        Ok(HealthDetailReply { detail: Some(d), .. }) => Ok(d.refused_peers.get("8080").copied().unwrap_or(0)),
        Ok(r) => Err(format!("/health/detail answered {} without a detail", r.status)),
        Err(e) => Err(format!("/health/detail failed: {e}")),
    }
}

/// Is `guard` tree B's fallback (`log`), or `off`: a guard that refuses
/// nothing on 8080 and 9418, where only the bearer holds? A mode not
/// reported is judged as `on`.
fn bearer_only(guard: Option<&str>) -> bool {
    matches!(guard, Some("log" | "off"))
}

/// What the default VM's transcript says ([`firewall_agent_script`]), into
/// `notes`, `exposures` and `gaps` for [`probes::verdict_in_vm_firewall`]: a
/// forged hook the guard did not refuse 403 exposes 9000; uid 1000's own
/// 8080 and 9418 requests are judged by `guard` (`/health/detail`'s
/// `agent_guard`, in the note): `on`, or a mode not reported, must refuse
/// each 403; under tree B's fallback ([`bearer_only`]) `GET /health`
/// answering 200 is the public summary and a bearer path answering 401 is
/// held by the bearer, and anything else but a 403 exposes the port; every
/// foreign listener as [`judge_foreign`] says; no VM address is a
/// `vm-address` gap.
fn judge_firewall(text: &str, foreign: &[(String, u16)], guard: Option<&str>, notes: &mut Vec<String>, exposures: &mut Vec<u16>, gaps: &mut Vec<&'static str>) {
    let code = |key: &str| marker(text, key).and_then(|v| v.trim().parse::<u16>().ok());
    for key in ["hook-resume-lo", "hook-resume-self", "hook-term-lo", "hook-term-self"] {
        if let Some(c) = code(key) {
            notes.push(format!("{key}={c}"));
            if c != 403 {
                exposures.push(9000);
            }
        }
    }
    notes.push(format!("agent_guard={}", guard.unwrap_or("? (no /health/detail: judged as on)")));
    // (marker, what, port, the answer that holds under the fallback)
    for (key, what, port, held) in [("local-8080", "agent GET 8080/health", 8080, 200), ("detail-8080", "agent GET 8080/health/detail", 8080, 401), ("local-9418", "agent 9418", 9418, 401)] {
        let Some(c) = code(key) else { continue };
        if bearer_only(guard) && c == held {
            let why = if held == 200 { "the public summary" } else { "refused by the bearer" };
            notes.push(format!("{what}={c} ({why}; agent_guard {})", guard.unwrap_or_default()));
            continue;
        }
        notes.push(format!("{what}={c}"));
        if c != 403 {
            exposures.push(port);
        }
    }
    judge_foreign(text, foreign, notes, exposures, gaps);
    notes.push(format!("NoNewPrivs={}", marker(text, "nnp").unwrap_or("?")));
    notes.push(format!("IMDS {}", marker(text, "imds").unwrap_or("?")));
    notes.push(format!("nf_tables symbols={}", marker(text, "nft").unwrap_or("?")));
    let vmip = marker(text, "vmip").unwrap_or("none");
    notes.push(format!("vm address {vmip}"));
    // The via-own-address forged hooks run only when the VM's own IPv4 was
    // found (`@@vmip`); if it was not, that check (critic M6a) was skipped, so
    // the verdict must not read as a clean `guarded`.
    if vmip == "none" || vmip.is_empty() {
        gap(gaps, "vm-address");
    }
    let setuid: Vec<&str> = text.lines().skip_while(|l| l.trim() != "@@setuid-begin").skip(1).take_while(|l| l.trim() != "@@setuid-end").filter(|l| !l.trim().is_empty()).collect();
    notes.push(format!("setuid binaries: {}", if setuid.is_empty() { "none".to_string() } else { setuid.join(",") }));
}

/// The RST abort's transcript ([`firewall_rst_script`]), judged by `rose`
/// (how far the guard's 8080 refusal count, [`refused_8080`], rose over that
/// spawn alone, or why it could not be read), into `notes`, `exposures` and
/// `gaps`. Under `on`, or a mode not reported, each connection adds two
/// refusals, its live `GET` and its aborted one: fewer means an aborted
/// request was not refused — admitted (the guard took the VM's own address
/// for remote), or never read: the shim's log tells which (`ai-env: guard
/// port=8080 peer=<$V>:…`) — and exposes 8080; no transcript, no connection
/// made, or a count that could not be read is an `rst-abort` gap, and no VM
/// address a `vm-address` one. Under tree B's fallback ([`bearer_only`]) the
/// guard refuses and counts nothing on 8080: noted only.
fn judge_rst(text: &str, guard: Option<&str>, rose: Result<u64, String>, notes: &mut Vec<String>, exposures: &mut Vec<u16>, gaps: &mut Vec<&'static str>) {
    let vmip = marker(text, "vmip").filter(|v| !v.is_empty() && *v != "none");
    let made = marker(text, "rst-8080").and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(0);
    let head = vmip.map_or_else(|| "RST abort through the VM's own address".to_string(), |ip| format!("RST abort via {}: {made} connections", socket(ip, 8080)));
    if bearer_only(guard) {
        notes.push(format!("{head}, not judged (agent_guard {}: nothing is refused or counted on 8080)", guard.unwrap_or_default()));
        return;
    }
    if vmip.is_none() {
        // `@@vmip none`: nowhere to send it; no `@@vmip` at all: the script never ran.
        let (why, name) = if marker(text, "vmip").is_some() { ("not sent (no address)", "vm-address") } else { ("no transcript", "rst-abort") };
        notes.push(format!("{head}: {why}"));
        gap(gaps, name);
        return;
    }
    match rose {
        _ if made == 0 => {
            notes.push(format!("{head} made"));
            gap(gaps, "rst-abort");
        }
        Err(why) => {
            notes.push(format!("{head}, the guard's refusals unread ({why})"));
            gap(gaps, "rst-abort");
        }
        Ok(n) if n >= 2 * made => notes.push(format!("{head}, 8080 refusals +{n} (two per connection: its live GET and its aborted one)")),
        Ok(n) => {
            notes.push(format!("{head}, 8080 refusals +{n} of {}: an aborted GET /health was not refused (admitted, or never read: the shim's log tells which)", 2 * made));
            exposures.push(8080);
        }
    }
}

/// The firewall spawn ended in `Terminated` (`why`: the session's `hook_terminate`
/// event, or the shim's `draining`) and the control plane now says `state`.
/// RUNNING: the shim drained on a forged terminate hook while the VM itself
/// did not end — the exposure this probe exists to record (9000), with this
/// note. Anything else: the VM did end, and the error stands.
fn drained_by_forged_hook(why: String, state: &VmState) -> Result<String, BridgeError> {
    if *state == VmState::Running {
        Ok(format!("the firewall spawn ended ({why}) while the VM is RUNNING: a forged terminate hook was admitted"))
    } else {
        Err(BridgeError::Terminated(why))
    }
}

async fn in_vm_firewall<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Started) -> Result<ProbeOutcome, BridgeError> {
    if ctx.knobs.fake_api.is_some() {
        // Start one VM so the lifecycle and terminate guard are exercised, then refuse.
        let p = plan(ctx, &flags("in-vm-firewall", 900, None, None, true))?;
        let _ = s6_start(ctx, api, ep, &p, started).await?;
        return Err(s6_fake_refusal("in-vm-firewall"));
    }
    let dial = agent_dial(ctx);
    let mut notes = Vec::new();
    let mut exposures: Vec<u16> = Vec::new();
    let mut gaps: Vec<&str> = Vec::new();

    // ---- the default VM ----
    let p = plan(ctx, &flags("in-vm-firewall", 900, None, None, true))?;
    let (vm, row, target, mut out) = s6_start(ctx, api, ep, &p, started).await?;
    let tok = token::mint(api, &ctx.paths, &vm.id, APP_PORT, 10).await?;
    let policy = RunPolicy::from_cfg(&ctx.cfg.transport, &row, ctx.knobs.backoff_ms);
    let env = AgentEnv { api, ep, paths: &ctx.paths, target: target.clone(), policy, dial };

    // The guard mode, its 8080 refusal count and the listeners; then the RST abort alone, and the count again.
    let before = detail_via(ep, &target, &tok).await;
    let guard = guard_mode(&before);
    let refused_before = refused_8080(&before);
    let foreign = foreign_listeners(before, &mut notes, &mut gaps);
    let (rst, _, _, rst_ended) = exec_agent_partial(&env, SpawnSpec { argv: vec!["bash".into(), "-c".into(), firewall_rst_script()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60) }, Vec::new()).await;
    if let Err(e) = rst_ended {
        notes.push(format!("the RST abort's spawn: {e}"));
    }
    let rose = refused_8080(&detail_via(ep, &target, &tok).await).and_then(|after| refused_before.map(|b| after.saturating_sub(b)));

    let mut argv = vec!["bash".to_string(), "-c".to_string(), firewall_agent_script(), "firewall".to_string()];
    for (addr, port) in &foreign {
        argv.push(addr.clone());
        argv.push(port.to_string());
    }
    let (stdout, _stderr, _pid, ended) = exec_agent_partial(&env, SpawnSpec { argv, cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60) }, Vec::new()).await;
    match ended {
        Ok(_) => {}
        // A drain ends every spawn (`hook_terminate`): recorded with what the script printed before it, never an abort.
        Err(BridgeError::Terminated(why)) => {
            let state = api.get(&vm.id).await?.state;
            notes.push(drained_by_forged_hook(why, &state)?);
            exposures.push(9000);
        }
        Err(e) => return Err(e),
    }
    judge_firewall(&String::from_utf8_lossy(&stdout), &foreign, guard.as_deref(), &mut notes, &mut exposures, &mut gaps);
    judge_rst(&String::from_utf8_lossy(&rst), guard.as_deref(), rose, &mut notes, &mut exposures, &mut gaps);

    // The forged hooks must not have drained the VM.
    match ep.get_health(&target.endpoint, &tok, APP_PORT).await {
        Ok(r) => {
            let draining = r.health.as_ref().is_some_and(|h| h.status == crate::wire::frame::HealthStatus::Draining);
            notes.push(format!("after forged hooks: /health {} ({})", r.status, if draining { "DRAINING" } else { "not draining" }));
            if draining {
                exposures.push(9000);
            }
        }
        Err(e) => notes.push(format!("after forged hooks: /health unreadable ({e})")),
    }
    // The side channels' bearer: without the bearer → 401, with it → 200; the code port's PUT /seed without it → 401.
    let with_bearer = detail_via(ep, &target, &tok).await.map_or_else(|e| format!("err {e}"), |d| d.status.to_string());
    let without_bearer = bearerless_detail(ep, &target, &tok).await.map_or_else(|e| format!("err {e}"), |s| s.to_string());
    let seed = match token::mint(api, &ctx.paths, &vm.id, 9418, 5).await {
        Ok(t) => bearerless_seed(&target.endpoint, &t).await.map_or_else(|e| format!("err {e}"), |s| s.to_string()),
        Err(e) => format!("no Port(9418) token ({e})"),
    };
    notes.push(format!("/health/detail bearer-less={without_bearer} with-bearer={with_bearer}; PUT /seed (Port 9418) bearer-less={seed}"));

    // ---- the --shell VM (a lab-only exception to the shell-row refusal; recorded, not in the default-VM verdict) ----
    let shell_note = match plan(ctx, &firewall_shell_flags()) {
        Ok(sp) => match s6_start(ctx, api, ep, &sp, started).await {
            Ok((svm, srow, starget, _)) => in_vm_firewall_shell(ctx, api, ep, &dial, &svm, &srow, &starget).await.unwrap_or_else(|e| format!("--shell VM: {e}")),
            Err(e) => format!("--shell VM not started: {e}"),
        },
        Err(e) => format!("--shell VM plan: {e}"),
    };
    notes.push(shell_note);

    out.verdict = probes::verdict_in_vm_firewall(&exposures, &gaps);
    out.note = notes.join("; ");
    Ok(out)
}

/// The `--shell` VM: the platform shell's own `id -u` and LISTEN rows (root,
/// through `vm::shell::run_script`, [`platform_shell_script`]), and whether
/// the agent (run_spawn) can reach 8022 ([`FIREWALL_SHELL_8022`]).
async fn in_vm_firewall_shell<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, dial: &AgentDial, svm: &VmInfo, srow: &VmRow, starget: &AgentTarget) -> Result<String, BridgeError> {
    let nonce = egress::check::new_nonce();
    let platform = shell::run_script(api, &svm.id, &platform_shell_script(&nonce), Duration::from_secs(30), ShellAuth::Header).await?;
    // As the agent: can uid 1000 reach 8022? `run_spawn` refuses a `--shell` row's target until that very
    // question is answered (D1, critic H2), so this one spawn, on the probe's own short `--shell` VM, runs
    // with `shell` cleared: the plan's lab-only exception, and the only one.
    let policy = RunPolicy::from_cfg(&ctx.cfg.transport, srow, ctx.knobs.backoff_ms);
    let target = AgentTarget { shell: false, ..starget.clone() };
    let env = AgentEnv { api, ep, paths: &ctx.paths, target, policy, dial: *dial };
    let (out, _, _, _) = exec_agent(&env, SpawnSpec { argv: vec!["bash".into(), "-c".into(), firewall_shell_script()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60) }, Vec::new()).await?;
    Ok(format!("--shell VM: {}; {}", platform_shell_note(&platform, &nonce), shell8022_note(&String::from_utf8_lossy(&out))))
}

/// A `/proc/net/tcp` or `tcp6` local address (`0100007F:1F90`: the address
/// as hex words in host byte order, little-endian on the VM; the port
/// big-endian) as `addr:port`, `[v6]:port`; a v4-mapped address as IPv4.
fn proc_net_addr(s: &str) -> Option<String> {
    let (hex, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let mut bytes = Vec::with_capacity(16);
    for i in (0..hex.len()).step_by(8) {
        bytes.extend(u32::from_str_radix(hex.get(i..i + 8)?, 16).ok()?.to_le_bytes());
    }
    let ip = match bytes.len() {
        4 => std::net::IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
        16 => {
            let v6 = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
            v6.to_ipv4_mapped().map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4)
        }
        _ => return None,
    };
    Some(socket(&ip.to_string(), port))
}

/// The platform shell's transcript (the echoed script, prompts, CRLF, then
/// the output of [`platform_shell_script`]) for the note: its uid and LISTEN
/// rows, read only from this run's marker lines; a transcript without the
/// `end` marker says so.
fn platform_shell_note(transcript: &str, nonce: &str) -> String {
    let mark = format!("@@AIENV{nonce}");
    let (mut uid, mut listens, mut finished) = (None, Vec::new(), false);
    for line in transcript.split('\n') {
        let Some(at) = line.find(&mark) else { continue };
        let rest = &line[at + mark.len()..];
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let mut w = rest.split_whitespace();
        match w.next() {
            Some("uid") => uid = w.next(),
            Some("listen") => {
                if let (Some(addr), Some(u), Some(inode)) = (w.next(), w.next(), w.next()) {
                    listens.push(format!("{} uid {u} inode {inode}", proc_net_addr(addr).unwrap_or_else(|| addr.to_string())));
                }
            }
            Some("end") => finished = true,
            _ => {}
        }
    }
    let rows = if listens.is_empty() { String::new() } else { format!(" ({})", listens.join(", ")) };
    let cut = if finished { "" } else { " (the transcript ended before its end marker)" };
    format!("platform shell id -u={}, {} LISTEN sockets{rows}{cut}", uid.unwrap_or("?"), listens.len())
}

/// The `--shell` VM's 8022 dials ([`FIREWALL_SHELL_8022`]) for the note.
fn shell8022_note(text: &str) -> String {
    let dials = markers(text, "shell8022");
    let reached = if dials.is_empty() { "not dialed".to_string() } else { dials.join(", ") };
    let vmip = marker(text, "vmip").unwrap_or("none");
    let own = if vmip == "none" || vmip.is_empty() { " (the VM's own address was not found: not dialed there)" } else { "" };
    format!("agent→8022 {reached}{own}")
}

/// A bearer-less `GET /health/detail` through the endpoint: its HTTP status
/// (expected 401). Uses the endpoint client's own bearer slot with an empty
/// bearer, which the shim's auth layer refuses.
async fn bearerless_detail<E: EndpointClient>(ep: &E, target: &AgentTarget, token: &AuthToken) -> Result<u16, BridgeError> {
    ep.get_health_detail(&target.endpoint, token, &Secret::new(String::new())).await.map(|d| d.status)
}

/// A bearer-less `PUT /seed` through the endpoint with a `Port(9418)`
/// token: its HTTP status (expected 401: the code port's bearer layer
/// refuses every path without the bearer). Sent by `tls::reqwest_client()`,
/// the side channels' one TLS policy (never redirected).
async fn bearerless_seed(endpoint: &str, token: &AuthToken) -> Result<u16, BridgeError> {
    let url = health::endpoint_url(endpoint, "/seed")?;
    let client = crate::bridge::tls::reqwest_client().map_err(|e| BridgeError::Sdk { op: "tls", message: format!("cannot build the HTTPS client: {e}") })?;
    let resp = client.execute(seed_request(&url, token)?).await.map_err(|e| BridgeError::Endpoint(format!("PUT {url}: {e}")))?;
    Ok(resp.status().as_u16())
}

/// `PUT url` with the endpoint token headers (`x-aws-proxy-auth`, marked
/// sensitive, and `x-aws-proxy-port: <token.port>`), no body and no
/// `Authorization`, within [`health::REQUEST_TIMEOUT`]. The empty body is
/// said (`content-length: 0`; hyper sends no length for an empty HTTP/1.1
/// body), so a front proxy that wants a length on a PUT cannot answer 411 in
/// place of the bearer layer's 401.
fn seed_request(url: &str, token: &AuthToken) -> Result<reqwest::Request, BridgeError> {
    let url = reqwest::Url::parse(url).map_err(|e| BridgeError::Endpoint(format!("{url}: {e}")))?;
    let mut auth = reqwest::header::HeaderValue::from_str(token.value()?.expose()).map_err(|_| BridgeError::Endpoint("the endpoint token is not a valid header value".into()))?;
    auth.set_sensitive(true);
    let mut req = reqwest::Request::new(reqwest::Method::PUT, url);
    req.headers_mut().insert("x-aws-proxy-auth", auth);
    req.headers_mut().insert("x-aws-proxy-port", reqwest::header::HeaderValue::from(token.port));
    req.headers_mut().insert(reqwest::header::CONTENT_LENGTH, reqwest::header::HeaderValue::from_static("0"));
    *req.timeout_mut() = Some(health::REQUEST_TIMEOUT);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::{
        dns_path_note, drained_by_forged_hook, e0_sockets, e1_hold, e5_http_phase, e5_reconnect, e5_resume, firewall_agent_script, firewall_shell_flags, firewall_shell_script, foreign_listeners, guard_mode, judge_firewall, judge_foreign, judge_rst, markers, open_hello,
        platform_shell_note, platform_shell_script, proc_net_addr, refused_8080, seed_request, shell8022_note, transport, upgraded, AgentConn, AgentDial, AgentTarget, AuthToken, BridgeError, Ctx, Duration, Frame, HealthDetailReply, Instant, MicrovmApi, Secret, UpgradeAuth,
        HealthDetail, VmInfo, VmState, APP_PORT, FIREWALL_COMMON, FIREWALL_FOREIGN, FIREWALL_RST, REATTACH_PRODUCER,
    };
    use crate::bridge::api::{EndpointClient, FakeMicrovmApi, HealthReply, IdleSpec, ImageInfo, ImageVersion, ManagedImage, RunSpec, VmSummary, FAKE_IMAGE_ARN, TOKEN_HEADER};
    use crate::bridge::config::{BridgeConfig, Paths};
    use crate::bridge::egress::check::FAKE_SHELL_NOTE;
    use crate::bridge::lab::VmKnobs;
    use crate::bridge::probes::{verdict_e0, verdict_e1, verdict_in_vm_firewall};
    use crate::wire::time::unix_now_ms;
    use futures_util::{SinkExt, StreamExt};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::Message;

    /// A host the endpoint pin accepts; the loopback dials (`AgentDial::local`) never resolve it.
    const ENDPOINT: &str = "bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws";

    /// A `/health/detail` body: a minimal one with `patch`'s fields over it.
    fn detail(patch: serde_json::Value) -> HealthDetail {
        let mut d = serde_json::json!({
            "status": "ok", "shim_version": "0.1.0", "run_hook_seen": true, "uptime_s": 1, "hook_source": "peer", "agent_guard": "on",
            "refused_peers": {}, "hook_peers": {}, "sockets_open": 0, "sockets_authenticated": 0, "spawns": [], "has_credentials": false, "listeners": [],
        });
        if let (Some(d), serde_json::Value::Object(p)) = (d.as_object_mut(), patch) {
            d.extend(p);
        }
        serde_json::from_value(d).unwrap()
    }

    /// in-vm-firewall tries every listener the shim does not own, at the
    /// address it listens on, and records the whole inventory with the
    /// platform's hook clients; when it cannot see them all (no detail, or
    /// listeners left out) it says so, as a `listeners` gap instead of a
    /// clean `guarded`.
    #[test]
    fn the_firewall_probe_sees_every_foreign_listener_or_names_a_gap() {
        let reply = |omitted: u64| {
            let d = serde_json::from_value(serde_json::json!({
                "status": "ok", "shim_version": "0.1.0", "run_hook_seen": true, "uptime_s": 1, "hook_source": "peer", "agent_guard": "on",
                "refused_peers": {}, "hook_peers": {"run": {"peer": "127.0.0.1:41234", "family": 4, "uid": 0, "inode": 777, "decision": "admitted", "at": "2026-10-03T12:00:00Z"}},
                "sockets_open": 0, "sockets_authenticated": 0, "spawns": [], "has_credentials": false,
                "listeners": [{"addr": "0.0.0.0", "port": 8080, "uid": 0, "inode": 1, "own": true}, {"addr": "::1", "port": 8022, "uid": 0, "inode": 2, "own": false}],
                "listeners_omitted": omitted,
            }))
            .unwrap();
            Ok(HealthDetailReply { status: 200, proxy_error: None, retry_after_s: None, detail: Some(d), body: String::new() })
        };
        let run = |r| {
            let (mut notes, mut gaps) = (Vec::new(), Vec::new());
            let listeners = foreign_listeners(r, &mut notes, &mut gaps);
            (listeners, gaps, notes.join("; "))
        };
        let inventory = "listeners: 0.0.0.0:8080 uid 0 inode 1 own, [::1]:8022 uid 0 inode 2; hook peers: run 127.0.0.1:41234 fam 4 uid 0 inode 777 admitted";
        assert_eq!(run(reply(0)), (vec![("::1".to_string(), 8022)], vec![], inventory.to_string()));
        assert_eq!(run(reply(91)), (vec![("::1".to_string(), 8022)], vec!["listeners"], format!("{inventory}; /health/detail left 91 listeners out")));
        let (listeners, gaps, note) = run(Ok(HealthDetailReply { status: 403, proxy_error: None, retry_after_s: None, detail: None, body: String::new() }));
        assert_eq!((listeners, gaps, note.as_str()), (vec![], vec!["listeners"], "/health/detail answered 403 without a detail"));
        let (listeners, gaps, note) = run(Err(BridgeError::Protocol("cut".into())));
        assert!(listeners.is_empty() && gaps == ["listeners"] && note.starts_with("/health/detail failed: "), "{note}");
    }

    /// `script` in /bin/bash (no rc files, a clean environment; first on
    /// PATH a `timeout` that runs its command and a `curl` that answers
    /// nothing) with `args` as `$1…`, killed after 60 s: its stdout.
    fn run_bash(script: &str, args: &[String]) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [("timeout", "#!/bin/sh\nshift\nexec \"$@\"\n"), ("curl", "#!/bin/sh\nexit 7\n")] {
            std::fs::write(dir.path().join(name), body).unwrap();
            std::fs::set_permissions(dir.path().join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let child = std::process::Command::new("/bin/bash")
            .args(["--norc", "--noprofile", "-c", script, "firewall"])
            .args(args)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(out) => String::from_utf8_lossy(&out.unwrap().stdout).into_owned(),
            Err(_) => {
                let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
                panic!("bash did not finish within 60 s");
            }
        }
    }

    /// Every foreign listener is dialed where it listens (critic H2): a ::1
    /// listener is reached at ::1 (at 127.0.0.1 it is refused, which read as
    /// `guarded`), a wildcard at loopback and at the VM's own address; a
    /// wildcard without that address, an IPv6 link-local listener or one the
    /// script never reported is a `listeners` gap. Real listeners on this
    /// host, the script's own dial loop in bash.
    #[test]
    fn the_firewall_dials_every_foreign_listener_where_it_listens() {
        let v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
        let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let any = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let port = |l: &std::net::TcpListener| l.local_addr().unwrap().port();
        let foreign = vec![("::1".to_string(), port(&v6)), ("127.0.0.1".to_string(), port(&v4)), ("0.0.0.0".to_string(), port(&any)), ("127.0.0.1".to_string(), closed)];
        let args: Vec<String> = foreign.iter().flat_map(|(a, p)| [a.clone(), p.to_string()]).collect();
        let judge = |text: &str| {
            let (mut notes, mut exposures, mut gaps) = (Vec::new(), Vec::new(), Vec::new());
            judge_foreign(text, &foreign, &mut notes, &mut exposures, &mut gaps);
            (exposures, gaps, notes)
        };
        // No /proc/net/fib_trie here: the VM's own address is not found, so the wildcard is dialed at loopback only.
        let text = run_bash(&[FIREWALL_COMMON, FIREWALL_FOREIGN].concat(), &args);
        let (exposures, gaps, notes) = judge(&text);
        assert_eq!(exposures, [port(&v6), port(&v4), port(&any)], "{text}");
        assert_eq!(gaps, ["listeners"], "a wildcard not dialed at the VM's own address: {text}");
        assert_eq!(notes[0], format!("foreign listener [::1]:{}: ::1 connect http:000", port(&v6)));
        assert!(notes[2].ends_with("127.0.0.1 connect http:000, vm-address undialed") && notes[3].ends_with(": 127.0.0.1 refused http:000"), "{notes:?}");
        // With the VM's address (loopback stands in for it) every wildcard is dialed everywhere it listens.
        let text = run_bash(&[FIREWALL_COMMON, "V=127.0.0.1\n", FIREWALL_FOREIGN].concat(), &args);
        assert_eq!(judge(&text).0, [port(&v6), port(&v4), port(&any)], "{text}");
        assert!(judge(&text).1.is_empty(), "{text}");
        // A listener the script never reported was not tried.
        let (exposures, gaps, notes) = judge("@@vmip 10.0.1.23\n");
        assert!(exposures.is_empty() && gaps == ["listeners"] && notes.iter().all(|n| n.ends_with(": not dialed")), "{notes:?}");
        // An IPv6 link-local listener cannot be dialed without its interface, which /proc/net/tcp6 does not name.
        let link_local = [("fe80::1".to_string(), 8022)];
        let text = run_bash(&[FIREWALL_COMMON, FIREWALL_FOREIGN].concat(), &["fe80::1".to_string(), "8022".to_string()]);
        let (mut notes, mut exposures, mut gaps) = (Vec::new(), Vec::new(), Vec::new());
        judge_foreign(&text, &link_local, &mut notes, &mut exposures, &mut gaps);
        assert_eq!((exposures, gaps, notes), (vec![], vec!["listeners"], vec!["foreign listener [fe80::1]:8022: no-scope undialed".to_string()]), "{text}");
    }

    /// The `--shell` VM's agent dials the platform shell's port at 127.0.0.1,
    /// ::1 and the VM's own address: a ::1-only listener is reached (a free
    /// port stands in for 8022 here), and a VM address that was not found is
    /// said.
    #[test]
    fn the_shell_vm_dials_8022_at_both_loopbacks_and_its_own_address() {
        let v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port = v6.local_addr().unwrap().port();
        let script = firewall_shell_script().replace("/8022\"", &format!("/{port}\"")).replace(":8022/", &format!(":{port}/"));
        let text = run_bash(&script, &[]);
        assert_eq!(markers(&text, "shell8022"), ["127.0.0.1 refused http:000", "::1 connect http:000"], "{text}");
        assert_eq!(shell8022_note(&text), "agent→8022 127.0.0.1 refused http:000, ::1 connect http:000 (the VM's own address was not found: not dialed there)");
    }

    /// The benign forged hooks (`/resume`) go first and every forged
    /// terminate last, after every other check: one the guard admits drains
    /// the VM and ends the script, and what it printed before still counts.
    #[test]
    fn the_forged_terminate_hooks_come_last() {
        let s = firewall_agent_script();
        let first_terminate = s.find("$P/terminate").expect("a forged terminate hook");
        for check in ["$P/resume", "@@local-8080", "@@detail-8080", "@@local-9418", "@@nnp", "@@setuid-begin", "@@imds", "@@nft", "@@foreign"] {
            assert!(s.find(check).is_some_and(|at| at < first_terminate), "{check} must come before the first forged terminate");
        }
        assert!(s.rfind("$P/resume").is_some_and(|at| at < first_terminate));
        assert!(s.find("POST %s/terminate").is_some_and(|at| at > first_terminate), "the close-before-lookup sends come last too");
    }

    /// A forged terminate the guard admitted drains the VM and ends the
    /// firewall spawn with `hook_terminate`: while the control plane still
    /// says RUNNING that is `exposed:9000`, recorded with what the script
    /// printed before the drain — never an abort; a VM that really ended
    /// stays an error.
    #[test]
    fn a_drain_by_a_forged_hook_is_recorded_as_exposed_9000() {
        let why = "microvm-x is terminating (event hook_terminate)".to_string();
        let note = drained_by_forged_hook(why.clone(), &VmState::Running).unwrap();
        assert!(note.contains(&why) && note.ends_with("a forged terminate hook was admitted"), "{note}");
        for state in [VmState::Terminating, VmState::Terminated] {
            assert!(matches!(drained_by_forged_hook(why.clone(), &state), Err(BridgeError::Terminated(m)) if m == why), "{state:?}");
        }
        let partial = "@@vmip 10.0.1.23\n@@hook-resume-lo 403\n@@hook-resume-self 403\n@@local-8080 403\n@@local-9418 403\n";
        let (mut notes, mut exposures, mut gaps) = (vec![note], vec![9000], Vec::new());
        judge_firewall(partial, &[], Some("on"), &mut notes, &mut exposures, &mut gaps);
        assert_eq!(verdict_in_vm_firewall(&exposures, &gaps), "exposed:9000");
        assert!(notes.iter().any(|n| n == "hook-resume-self=403") && notes.iter().any(|n| n == "agent 9418=403"), "{notes:?}");
    }

    /// uid 1000's own 8080 and 9418 requests are judged by the guard mode
    /// `/health/detail` reported (tree B): `on`, or no mode, must refuse each
    /// 403; under the fallback (`log`, `off`) only the bearer holds, so `GET
    /// /health` answering 200 is the public summary and a bearer path
    /// answering 401 holds, while a 200 on a bearer path, any other answer
    /// but a 403, an admitted hook and a foreign listener stay exposures. The
    /// mode is in the note.
    #[test]
    fn the_firewall_judges_8080_and_9418_by_the_guard_mode() {
        let judge = |text: &str, guard: Option<&str>, foreign: &[(String, u16)]| {
            let (mut notes, mut exposures, mut gaps) = (Vec::new(), Vec::new(), Vec::new());
            judge_firewall(text, foreign, guard, &mut notes, &mut exposures, &mut gaps);
            (exposures, gaps, notes)
        };
        let checks = |health: &str, detail: &str, code: &str| format!("@@vmip 10.0.1.23\n@@hook-resume-lo 403\n@@hook-resume-self 403\n@@local-8080 {health}\n@@detail-8080 {detail}\n@@local-9418 {code}\n");
        let bearer_holds = checks("200", "401", "401");
        for mode in ["log", "off"] {
            let (exposures, gaps, notes) = judge(&bearer_holds, Some(mode), &[]);
            assert_eq!(verdict_in_vm_firewall(&exposures, &gaps), "guarded", "{mode}: {notes:?}");
            for said in [format!("agent_guard={mode}"), format!("agent GET 8080/health=200 (the public summary; agent_guard {mode})"), format!("agent GET 8080/health/detail=401 (refused by the bearer; agent_guard {mode})"), format!("agent 9418=401 (refused by the bearer; agent_guard {mode})")] {
                assert!(notes.contains(&said), "{said:?} not in {notes:?}");
            }
            assert!(judge(&checks("403", "403", "403"), Some(mode), &[]).0.is_empty(), "{mode}: a refusal is never an exposure");
        }
        // The same answers under `on`, or with no mode reported: the guard let uid 1000 through.
        for guard in [Some("on"), None] {
            assert_eq!(judge(&bearer_holds, guard, &[]).0, [8080, 8080, 9418], "{guard:?}");
        }
        assert!(judge(&bearer_holds, None, &[]).2.contains(&"agent_guard=? (no /health/detail: judged as on)".to_string()));
        let (exposures, gaps, notes) = judge(&checks("403", "403", "403"), Some("on"), &[]);
        assert!(exposures.is_empty() && gaps.is_empty() && notes.contains(&"agent_guard=on".to_string()) && notes.contains(&"agent 9418=403".to_string()), "{notes:?}");
        // Under the fallback: a 200 on a bearer path, an answer that is no refusal, an admitted hook, a foreign listener.
        assert_eq!(judge(&checks("200", "200", "401"), Some("log"), &[]).0, [8080]);
        assert_eq!(judge(&checks("200", "401", "200"), Some("log"), &[]).0, [9418]);
        assert_eq!(judge(&checks("000", "401", "404"), Some("log"), &[]).0, [8080, 9418]);
        assert_eq!(judge(&bearer_holds.replace("@@hook-resume-lo 403", "@@hook-resume-lo 200"), Some("log"), &[]).0, [9000]);
        let dialed = format!("{bearer_holds}@@foreign 127.0.0.1 8022 127.0.0.1 connect http:000\n");
        assert_eq!(judge(&dialed, Some("off"), &[("127.0.0.1".to_string(), 8022)]).0, [8022]);
    }

    /// The RST abort through the VM's own address (critic M6a's snapshot
    /// case) is judged by how far the guard's 8080 refusal count rose over
    /// its spawn: under `on`, or no mode, two per connection (its live GET
    /// and its aborted one); fewer exposes 8080; an unread count or no
    /// connection is an `rst-abort` gap, no VM address a `vm-address` one.
    /// Under the fallback (`log`, `off`) nothing is refused or counted on
    /// 8080: noted only. The count comes from `/health/detail`'s
    /// `refused_peers`, the mode from its `agent_guard`.
    #[test]
    fn the_rst_abort_is_judged_by_the_guards_refusal_count() {
        let judge = |text: &str, guard: Option<&str>, rose: Result<u64, String>| {
            let (mut notes, mut exposures, mut gaps) = (Vec::new(), Vec::new(), Vec::new());
            judge_rst(text, guard, rose, &mut notes, &mut exposures, &mut gaps);
            (exposures, gaps, notes.join("; "))
        };
        let made = "@@vmip 10.0.1.23\n@@rst-8080 5\n@@done\n";
        let (exposures, gaps, note) = judge(made, Some("on"), Ok(10));
        assert!(exposures.is_empty() && gaps.is_empty(), "{note}");
        assert_eq!(note, "RST abort via 10.0.1.23:8080: 5 connections, 8080 refusals +10 (two per connection: its live GET and its aborted one)");
        // A guard that took the VM's own address for remote admits the aborted GETs: fewer refusals than requests.
        for (guard, rose) in [(Some("on"), 5), (None, 9)] {
            let (exposures, gaps, note) = judge(made, guard, Ok(rose));
            assert!(exposures == [8080] && gaps.is_empty() && note.contains(&format!("+{rose} of 10: an aborted GET /health was not refused")), "{guard:?}: {note}");
        }
        assert_eq!(judge(made, Some("on"), Err("/health/detail failed: cut".into())).1, ["rst-abort"]);
        assert_eq!(judge("@@vmip 10.0.1.23\n@@rst-8080 0\n", Some("on"), Ok(0)).1, ["rst-abort"]);
        assert_eq!(judge("@@vmip 10.0.1.23\n", Some("on"), Ok(0)).1, ["rst-abort"], "the script never said");
        assert_eq!(judge("@@vmip none\n", Some("on"), Ok(0)), (vec![], vec!["vm-address"], "RST abort through the VM's own address: not sent (no address)".to_string()));
        assert_eq!(judge("", None, Err("/health/detail failed: cut".into())), (vec![], vec!["rst-abort"], "RST abort through the VM's own address: no transcript".to_string()), "the spawn never ran the script");
        for mode in ["log", "off"] {
            let (exposures, gaps, note) = judge(made, Some(mode), Ok(0));
            assert!(exposures.is_empty() && gaps.is_empty() && note == format!("RST abort via 10.0.1.23:8080: 5 connections, not judged (agent_guard {mode}: nothing is refused or counted on 8080)"), "{note}");
            assert!(judge("", Some(mode), Ok(0)).1.is_empty(), "{mode}: nothing to judge, so nothing missing");
        }
        // What the probe reads them from.
        let reply = |v: serde_json::Value| Ok(HealthDetailReply { status: 200, proxy_error: None, retry_after_s: None, detail: Some(detail(v)), body: String::new() });
        let read = reply(serde_json::json!({"agent_guard": "log", "refused_peers": {"8080": 3, "9418": 1}}));
        assert_eq!((guard_mode(&read).as_deref(), refused_8080(&read)), (Some("log"), Ok(3)));
        assert_eq!(refused_8080(&reply(serde_json::json!({"refused_peers": {"9418": 2}}))), Ok(0), "no refusal on 8080 yet");
        let no_detail = Ok(HealthDetailReply { status: 401, proxy_error: None, retry_after_s: None, detail: None, body: String::new() });
        assert_eq!((guard_mode(&no_detail), refused_8080(&no_detail)), (None, Err("/health/detail answered 401 without a detail".into())));
        assert!(refused_8080(&Err(BridgeError::Protocol("cut".into()))).is_err_and(|e| e.starts_with("/health/detail failed: ")));
    }

    /// The RST abort, run by bash against a local listener standing in for
    /// 8080 at `$V`: five connections, each carrying a whole `GET /health`
    /// whose answer it leaves unread, then a second whole one, after which
    /// the connection is reset, not closed: the request is queued for the
    /// shim to read while its client's socket is already gone.
    #[test]
    fn the_rst_abort_sends_a_whole_request_then_resets() {
        use std::io::{Read as _, Write as _};
        // Listening on ::1 only, with V=::1: the aborts must go through $V
        // (the VM's own address, the snapshot case), never to 127.0.0.1.
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..5 {
                let (mut tcp, _) = listener.accept().unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let (mut got, mut buf) = (Vec::new(), [0u8; 4096]);
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = tcp.read(&mut buf).unwrap();
                    assert!(n > 0, "the first request ended before its head did");
                    got.extend_from_slice(&buf[..n]);
                }
                tcp.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 2\r\n\r\n{}").unwrap();
                let ended = loop {
                    match tcp.read(&mut buf) {
                        Ok(0) => break "closed".to_string(),
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(e) => break format!("{:?}", e.kind()),
                    }
                };
                seen.push((String::from_utf8_lossy(&got).into_owned(), ended));
            }
            seen
        });
        let rst = FIREWALL_RST.replace("/8080\"", &format!("/{port}\""));
        assert_ne!(rst, FIREWALL_RST);
        let text = run_bash(&[FIREWALL_COMMON, "V=::1\n", &rst].concat(), &[]);
        assert_eq!(markers(&text, "rst-8080"), ["5"], "{text}");
        let twice = "GET /health HTTP/1.1\r\nHost: vm\r\n\r\n".repeat(2);
        for (got, ended) in server.join().unwrap() {
            assert_eq!((got.as_str(), ended.as_str()), (twice.as_str(), "ConnectionReset"));
        }
    }

    /// The bytes of one HTTP request head read from `tcp`.
    async fn request_head(tcp: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        let (mut head, mut buf) = (Vec::new(), [0u8; 1024]);
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tcp.read(&mut buf).await.unwrap();
            assert!(n > 0, "the request ended before its head did");
            head.extend_from_slice(&buf[..n]);
        }
        head
    }

    /// e0 counts the header token's upgrade only when the client took the
    /// 101: a 101 whose `Connection` is not exactly `Upgrade` (tungstenite
    /// refuses it) opened no WebSocket and renders `101-refused`, never the
    /// catalog's pass; a real upgrade renders `101`.
    #[tokio::test]
    async fn e0_counts_a_101_only_when_the_client_took_it() {
        use tokio::io::AsyncWriteExt as _;
        let auth = || UpgradeAuth::Header { token: Secret::new("endpoint-token-for-e0".into()), port: APP_PORT };
        let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = refusing.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut tcp, _) = refusing.accept().await.unwrap();
            request_head(&mut tcp).await;
            tcp.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade, keep-alive\r\nSec-WebSocket-Accept: x\r\n\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let probe = transport::upgrade_probe(&AgentDial { local: Some(at) }, ENDPOINT, auth()).await.unwrap();
        assert!(probe.status == 101 && probe.refused.is_some() && !upgraded(&probe), "status {} refused {:?}", probe.status, probe.refused);
        assert_eq!(verdict_e0(probe.status, upgraded(&probe), &probe.version, 403, 403, 403), "101-refused HTTP/1.1 403 403 403");
        task.abort();
        let accepting = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = accepting.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = accepting.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _ = ws.next().await;
        });
        let probe = transport::upgrade_probe(&AgentDial { local: Some(at) }, ENDPOINT, auth()).await.unwrap();
        assert!(upgraded(&probe), "status {} refused {:?}", probe.status, probe.refused);
        assert_eq!(verdict_e0(probe.status, upgraded(&probe), &probe.version, 403, 403, 403), "101 HTTP/1.1 403 403 403");
        drop(probe);
        task.abort();
    }

    /// A loopback `/agent` that answers every `hello` with `hello_ok` and
    /// keeps `open` at the number of sockets open at it: a Close, or the
    /// socket's end, takes one off before the server lets go of the socket.
    async fn hello_server(open: Arc<AtomicU32>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let open = open.clone();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                    open.fetch_add(1, Ordering::SeqCst);
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_close() {
                            break;
                        }
                        if let Ok(Frame::Hello { .. }) = Frame::try_from(msg) {
                            let ok = Frame::HelloOk { wire: 1, shim_version: "0.1.0".into(), claude_version: None, microvm_id: None, image_version: None, boot_nonce: "0".repeat(32), owner: None, has_credentials: false, uptime_s: 1, run_hook_seen: true, spawns: vec![], resumed: vec![] };
                            let _ = ws.send(Message::from(&ok)).await;
                        }
                    }
                    open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        addr
    }

    /// An endpoint whose `/health/detail` reports the sockets open at the
    /// `/agent` server, and refuses the read while eight are open (the
    /// endpoint's cap of 8 connections per VM: the read would be a 9th).
    struct CappedEndpoint {
        open: Arc<AtomicU32>,
    }

    impl EndpointClient for CappedEndpoint {
        async fn get_health(&self, _endpoint: &str, _token: &AuthToken, _port_header: u16) -> Result<HealthReply, BridgeError> {
            Err(BridgeError::Endpoint("e0 reads no /health".into()))
        }
        async fn get_health_detail(&self, _endpoint: &str, _token: &AuthToken, _bearer: &Secret<String>) -> Result<HealthDetailReply, BridgeError> {
            Ok(match self.open.load(Ordering::SeqCst) {
                n if n >= 8 => HealthDetailReply { status: 429, proxy_error: None, retry_after_s: None, detail: None, body: String::new() },
                n => HealthDetailReply { status: 200, proxy_error: None, retry_after_s: None, detail: Some(detail(serde_json::json!({"sockets_open": n}))), body: String::new() },
            })
        }
    }

    /// e0 reads the shim's socket count once the 9th and one held socket
    /// closed (critic L3): with all eight held the endpoint's cap of 8
    /// connections per VM would refuse the read itself, and the note would
    /// say `?`. The note says which count it is: the held sockets still open.
    #[tokio::test]
    async fn e0_reads_the_socket_count_once_one_held_socket_closed() {
        let open = Arc::new(AtomicU32::new(0));
        let addr = hello_server(open.clone()).await;
        let target = AgentTarget { vm_id: "microvm-e0".into(), endpoint: ENDPOINT.into(), session_token: Secret::new("session-token-for-e0".into()), vpc: false, shell: false };
        let tok = AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new("endpoint-token-for-e0".into()))]), port: APP_PORT, expires_at_unix: 0 };
        let note = e0_sockets(&CappedEndpoint { open: open.clone() }, &AgentDial { local: Some(addr) }, &target, &tok, Duration::from_secs(5)).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            note,
            "8 of 8 sockets completed hello and stayed open, then the 9th socket completed hello (no cap hit); shim sockets_open=7, read with 7 held sockets open (the 9th and one held socket closed first: with all eight open the endpoint's cap would likely refuse the read)"
        );
    }

    /// A loopback `/agent` that answers every app `ping` with a `pong` until
    /// `quiet_at`; from then on it closes the socket (`close`) or keeps
    /// reading and answers nothing.
    async fn pong_server(quiet_at: tokio::time::Instant, close: bool) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                if tokio::time::Instant::now() >= quiet_at {
                    if close {
                        return;
                    }
                    continue;
                }
                if let Ok(Frame::Ping { ts }) = Frame::try_from(msg) {
                    let _ = ws.send(Message::from(&Frame::Pong { ts })).await;
                }
            }
        });
        addr
    }

    /// e1 renders `survives` only when the shim's pongs kept arriving past
    /// the token's expiry: an endpoint that stops forwarding at expiry
    /// without closing is `silent-at-expiry`, one that closes
    /// `cut-at-expiry`.
    #[tokio::test]
    async fn e1_survives_only_while_pongs_arrive_past_the_expiry() {
        let hold = |quiet_in: Duration, close: bool| async move {
            let expiry_ms = i64::try_from(unix_now_ms()).unwrap() + 400;
            let addr = pong_server(tokio::time::Instant::now() + quiet_in, close).await;
            let mut conn = AgentConn::open(&AgentDial { local: Some(addr) }, ENDPOINT, &Secret::new("endpoint-token-for-e1".into())).await.unwrap_or_else(|e| panic!("{e}"));
            e1_hold(&mut conn, expiry_ms, Duration::from_millis(2500), Duration::from_millis(50), Duration::from_millis(700)).await
        };
        assert_eq!(hold(Duration::from_secs(60), false).await, (None, None), "pongs all along");
        let (cut, silent) = hold(Duration::from_millis(400), false).await;
        assert!(cut.is_none() && silent.is_some_and(|s| s <= 0), "an open socket gone silent at the expiry: {cut:?} {silent:?}");
        assert_eq!(verdict_e1(cut, silent), "silent-at-expiry:0");
        let (cut, silent) = hold(Duration::from_millis(400), true).await;
        assert!(cut.is_some() && silent.is_none(), "closed at the expiry: {cut:?} {silent:?}");
    }

    /// A socket that went silent before the token's expiry and was held for
    /// less than `dead_after` past its last frame: only the after-the-hold
    /// check can name the silence (with a longer `dead_after` than the hold,
    /// the in-loop check never fires), so it never renders `survives`.
    #[tokio::test]
    async fn e1_names_a_silence_from_before_the_expiry_that_the_hold_outlasted() {
        let expiry_ms = i64::try_from(unix_now_ms()).unwrap() + 600;
        let addr = pong_server(tokio::time::Instant::now() + Duration::from_millis(200), false).await;
        let mut conn = AgentConn::open(&AgentDial { local: Some(addr) }, ENDPOINT, &Secret::new("endpoint-token-for-e1".into())).await.unwrap_or_else(|e| panic!("{e}"));
        let (cut, silent) = e1_hold(&mut conn, expiry_ms, Duration::from_millis(1500), Duration::from_millis(50), Duration::from_secs(5)).await;
        assert!(cut.is_none() && silent.is_some_and(|s| s <= 0), "quiet from before the expiry, never dead within the hold: {cut:?} {silent:?}");
        assert_eq!(verdict_e1(cut, silent), "silent-at-expiry:0");
    }

    /// A Ctx over `dir` with every poll scaled to `backoff_ms` ms a second.
    fn ctx(dir: &std::path::Path, backoff_ms: u64) -> Ctx {
        Ctx { paths: Paths::from_root_and_env(dir.to_path_buf(), None), cfg: BridgeConfig::default(), knobs: VmKnobs { backoff_ms: Some(backoff_ms), ..VmKnobs::default() } }
    }

    /// A RUNNING VM of `fake` with auto-resume and max idle 60 s, as e5 starts.
    async fn running_vm(fake: &FakeMicrovmApi) -> VmInfo {
        let idle = IdleSpec { max_idle_s: 60, suspended_s: 1500, auto_resume: true };
        let spec = RunSpec { image_arn: FAKE_IMAGE_ARN.into(), image_version: "1.0".into(), execution_role_arn: None, ingress_connectors: vec![], egress_connectors: vec![], idle, max_duration_s: 2400, run_hook_payload: "{}".into(), client_token: uuid::Uuid::now_v7().to_string() };
        let vm = fake.run(&spec).await.unwrap();
        fake.state().advance_all();
        fake.get(&vm.id).await.unwrap()
    }

    /// The crate's fake control plane, but a SUSPENDING VM settles SUSPENDED
    /// only at the `settle_on`-th GetMicrovm (a real suspend takes about
    /// 1.5 s; the fake's is instant).
    struct Settling {
        fake: FakeMicrovmApi,
        gets: AtomicU32,
        settle_on: u32,
    }

    impl MicrovmApi for Settling {
        async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
            self.fake.run(spec).await
        }
        async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
            let suspending = self.fake.state().vms.get(id).is_some_and(|v| v.state == VmState::Suspending);
            if self.gets.fetch_add(1, Ordering::SeqCst) + 1 == self.settle_on && suspending {
                self.fake.set_state(id, VmState::Suspended);
            }
            self.fake.get(id).await
        }
        async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
            self.fake.suspend(id).await
        }
        async fn resume(&self, id: &str) -> Result<(), BridgeError> {
            self.fake.resume(id).await
        }
        async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
            self.fake.terminate(id).await
        }
        async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
            self.fake.list(image_arn).await
        }
        async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
            self.fake.create_auth_token(id, minutes, port).await
        }
        async fn create_shell_token(&self, id: &str, minutes: u16) -> Result<AuthToken, BridgeError> {
            self.fake.create_shell_token(id, minutes).await
        }
        async fn get_image(&self, arn: &str) -> Result<ImageInfo, BridgeError> {
            self.fake.get_image(arn).await
        }
        async fn list_image_versions(&self, arn: &str) -> Result<Vec<ImageVersion>, BridgeError> {
            self.fake.list_image_versions(arn).await
        }
        async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
            self.fake.list_managed_images().await
        }
    }

    /// e5 resumes a VM that a phase left SUSPENDING only once it settled
    /// SUSPENDED: ResumeMicrovm answers Conflict until then, and a resume
    /// swallowed as "already resuming" left the VM suspended (the wait for
    /// RUNNING failed, and e5 recorded nothing).
    #[tokio::test]
    async fn e5_resumes_a_suspending_vm_once_it_settled() {
        let dir = tempfile::tempdir().unwrap();
        let api = Settling { fake: FakeMicrovmApi::new(), gets: AtomicU32::new(0), settle_on: 3 };
        let vm = running_vm(&api.fake).await;
        api.fake.set_state(&vm.id, VmState::Suspending);
        let mut notes = Vec::new();
        e5_resume(&ctx(dir.path(), 1), &api, &vm.id, &mut notes).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(api.fake.get(&vm.id).await.unwrap().state, VmState::Running);
        assert!(notes.len() == 1 && notes[0].starts_with("resumed in "), "{notes:?}");
    }

    /// e5 measures the reconnect to the suspended VM — after a suspend in
    /// progress settled — as a timed `/agent` dial with `hello`, and the
    /// state after: here the endpoint resumes the VM on the request
    /// (auto-resume) and the shim answers; with nothing listening the
    /// failure and the state after are the note.
    #[tokio::test]
    async fn e5_measures_the_reconnect_to_the_suspended_vm() {
        let dir = tempfile::tempdir().unwrap();
        let api = Arc::new(Settling { fake: FakeMicrovmApi::new(), gets: AtomicU32::new(0), settle_on: 2 });
        let vm = running_vm(&api.fake).await;
        api.fake.set_state(&vm.id, VmState::Suspending);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (endpoint, id) = (api.clone(), vm.id.clone());
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // The endpoint resumes the VM and holds the request through /resume.
            endpoint.fake.set_state(&id, VmState::Running);
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _ = ws.next().await; // the hello
            let ok = Frame::HelloOk { wire: 1, shim_version: "0.1.0".into(), claude_version: None, microvm_id: None, image_version: None, boot_nonce: "0".repeat(32), owner: None, has_credentials: false, uptime_s: 1, run_hook_seen: true, spawns: vec![], resumed: vec![] };
            ws.send(Message::from(&ok)).await.unwrap();
            while let Some(Ok(_)) = ws.next().await {}
        });
        let target = AgentTarget { vm_id: vm.id.clone(), endpoint: vm.endpoint.clone(), session_token: Secret::new("session-token-for-e5".into()), vpc: false, shell: false };
        let note = e5_reconnect(&ctx(dir.path(), 20), &*api, &AgentDial { local: Some(addr) }, &target, &vm.id).await;
        assert!(note.starts_with("reconnect to the SUSPENDED VM: hello_ok after ") && note.ends_with(" ms, then RUNNING"), "{note}");
        server.await.unwrap();
        api.fake.set_state(&vm.id, VmState::Suspended);
        let nothing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let note = e5_reconnect(&ctx(dir.path(), 20), &*api, &AgentDial { local: Some(nothing) }, &target, &vm.id).await;
        assert!(note.starts_with("reconnect to the SUSPENDED VM: endpoint: /agent dial to ") && note.ends_with(", then SUSPENDED"), "{note}");
    }

    /// The fake endpoint, plus the idle suspension that comes between two
    /// GETs: after the first GET the VM is SUSPENDED (the next GET resumes
    /// it: auto-resume).
    struct SuspendsAfterFirstGet<'a> {
        fake: &'a FakeMicrovmApi,
        id: String,
        gets: AtomicU32,
    }

    impl EndpointClient for SuspendsAfterFirstGet<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            let reply = self.fake.get_health(endpoint, token, port_header).await;
            if self.gets.fetch_add(1, Ordering::SeqCst) == 0 {
                self.fake.set_state(&self.id, VmState::Suspended);
            }
            reply
        }
    }

    /// e5's http phase is `kept` only when every GetMicrovm between the GETs
    /// said RUNNING: a suspension that the next GET undid (auto-resume) is
    /// `suspended`, though the VM is RUNNING again when the phase ends.
    #[tokio::test]
    async fn e5_http_phase_sees_a_suspension_between_gets() {
        let fake = FakeMicrovmApi::new();
        let vm = running_vm(&fake).await;
        let tok = fake.create_auth_token(&vm.id, 60, APP_PORT).await.unwrap();
        let target = AgentTarget { vm_id: vm.id.clone(), endpoint: vm.endpoint.clone(), session_token: Secret::new("session-token-for-e5".into()), vpc: false, shell: false };
        let ep = SuspendsAfterFirstGet { fake: &fake, id: vm.id.clone(), gets: AtomicU32::new(0) };
        let (kept, note) = e5_http_phase(&fake, &ep, &target, &tok, Duration::from_millis(300), Duration::from_millis(100), Duration::from_millis(10)).await.unwrap();
        assert!(!kept && note.starts_with("http: SUSPENDED at +0 s") && note.contains("RUNNING at the end"), "{note}");
        assert!(ep.gets.load(Ordering::SeqCst) >= 2, "the next GET resumed it");
        assert_eq!(fake.get(&vm.id).await.unwrap().state, VmState::Running, "one read at the end would have said kept");
        let steady = SuspendsAfterFirstGet { fake: &fake, id: "microvm-elsewhere".into(), gets: AtomicU32::new(0) };
        let (kept, note) = e5_http_phase(&fake, &steady, &target, &tok, Duration::from_millis(100), Duration::from_millis(50), Duration::from_millis(10)).await.unwrap();
        assert!(kept && note.starts_with("http: RUNNING at all "), "{note}");
    }

    /// A GetMicrovm poll of e5's http phase that fails (an error that
    /// outlived the SDK's retries) is counted in the note and the polling
    /// goes on: one must not end the 15–20 min e5. An error of the phase's
    /// final read still ends it, and so does a VM that is gone
    /// (`ResourceNotFound`, a terminal state) at any read.
    #[tokio::test]
    async fn e5_http_phase_counts_a_failed_poll_and_polls_on() {
        let fake = FakeMicrovmApi::new();
        let vm = running_vm(&fake).await;
        let tok = fake.create_auth_token(&vm.id, 60, APP_PORT).await.unwrap();
        let target = AgentTarget { vm_id: vm.id.clone(), endpoint: vm.endpoint.clone(), session_token: Secret::new("session-token-for-e5".into()), vpc: false, shell: false };
        let phase = |ms: u64| e5_http_phase(&fake, &fake, &target, &tok, Duration::from_millis(ms), Duration::from_millis(100), Duration::from_millis(10));
        let get_timeout = || BridgeError::Sdk { op: "get_microvm", message: "dispatch failure: operation timeout".into() };
        // The first two polls fail; every later one, and the final read, says RUNNING.
        fake.fail_on("get", get_timeout(), false);
        fake.fail_on("get", BridgeError::Throttled("Rate exceeded".into()), false);
        let (kept, note) = phase(300).await.unwrap_or_else(|e| panic!("{e}"));
        assert!(kept && note.starts_with("http: RUNNING at all ") && note.ends_with(" polls (2 more failed, the last: aws throttled (after retries): Rate exceeded)"), "{note}");
        // A zero-length phase has only its final read: that read's error ends it.
        fake.fail_on("get", get_timeout(), false);
        assert!(matches!(phase(0).await, Err(BridgeError::Sdk { op: "get_microvm", .. })));
        // A VM that is gone ends it at the first poll, as a terminal state does.
        fake.fail_on("get", BridgeError::VmNotFound(vm.id.clone()), false);
        assert!(matches!(phase(2_000).await, Err(BridgeError::VmNotFound(_))));
        fake.set_state(&vm.id, VmState::Terminated);
        assert!(matches!(phase(2_000).await, Err(BridgeError::Terminated(_))));
    }

    /// The reattach producer outlives the cut after its first chunk plus the
    /// D22 ladder (TERM at +0.8 s, KILL at +1.2 s) by a wide margin, so a lost
    /// socket that killed it shows (critic H1); it prints line-0 … line-19999
    /// once each, in order, and exits 0.
    #[test]
    fn the_reattach_producer_outlives_the_cut_and_the_ladder() {
        let t = Instant::now();
        let out = std::process::Command::new("/bin/sh").args(["-c", REATTACH_PRODUCER]).stdin(std::process::Stdio::null()).output().unwrap();
        let took = t.elapsed();
        assert!(out.status.success(), "{:?}", out.status);
        assert!(took >= Duration::from_secs(3), "the producer was done after {took:?}, before the ladder could have killed it");
        let expected: Vec<String> = (0..20_000).map(|i| format!("line-{i}")).collect();
        assert!(String::from_utf8_lossy(&out.stdout).lines().eq(expected.iter().map(String::as_str)), "line-0 … line-19999 in order, once each");
    }

    /// The platform shell echoes its input after a prompt, with CRLF: the
    /// uid and the LISTEN rows are read from this run's marker lines only,
    /// never from the echoed script (the transcript's first line) or the
    /// trailing prompt; `/proc/net/tcp`'s hex addresses are decoded.
    #[test]
    fn the_platform_shell_note_reads_only_this_runs_markers() {
        const NONCE: &str = "0123456789abcdef";
        let script = platform_shell_script(NONCE);
        assert!(script.ends_with("\nexit\n") && !script.contains(&format!("@@AIENV{NONCE}")), "{script}");
        let echoed: String = script.lines().map(|l| format!("λ $ {l}\r\n")).collect();
        let printed = format!(
            "@@AIENV{NONCE} uid 0\r\n@@AIENV{NONCE} listen 0100007F:1F90 0 1234\r\n@@AIENVfedcba9876543210 listen 00000000:0016 0 1\r\n@@AIENV{NONCE} listen 00000000000000000000000001000000:1F56 0 5678\r\n@@AIENV{NONCE} end\r\nλ $ "
        );
        let note = platform_shell_note(&format!("{echoed}{printed}"), NONCE);
        assert_eq!(note, "platform shell id -u=0, 2 LISTEN sockets (127.0.0.1:8080 uid 0 inode 1234, [::1]:8022 uid 0 inode 5678)");
        let cut = platform_shell_note(&format!("{echoed}@@AIENV{NONCE} uid 0\r\n"), NONCE);
        assert_eq!(cut, "platform shell id -u=0, 0 LISTEN sockets (the transcript ended before its end marker)");
        assert_eq!(platform_shell_note(&echoed, NONCE), "platform shell id -u=?, 0 LISTEN sockets (the transcript ended before its end marker)");
        assert_eq!(proc_net_addr("00000000:1F56").as_deref(), Some("0.0.0.0:8022"));
        assert_eq!(proc_net_addr("0000000000000000FFFF00000100007F:1F90").as_deref(), Some("127.0.0.1:8080"), "v4-mapped as IPv4");
        assert_eq!(proc_net_addr("00000000000000000000000000000000:2382").as_deref(), Some("[::]:9090"));
        for bad in ["0100007F", "0100007:1F90", "0100007F:XYZ", ""] {
            assert_eq!(proc_net_addr(bad), None, "{bad:?}");
        }
    }

    /// The bearer-less `PUT /seed`: the endpoint token in a sensitive
    /// `x-aws-proxy-auth` with `x-aws-proxy-port: 9418`, no body (said, as
    /// `content-length: 0`, so a front proxy has no reason for a 411), and
    /// no `Authorization` at all.
    #[test]
    fn the_seed_put_carries_the_port_9418_token_and_no_bearer() {
        let token = AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new("endpoint-token-for-seed".into()))]), port: 9418, expires_at_unix: 0 };
        let url = crate::bridge::vm::health::endpoint_url(ENDPOINT, "/seed").unwrap();
        let req = seed_request(&url, &token).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((req.method().as_str(), req.url().as_str()), ("PUT", format!("https://{ENDPOINT}/seed").as_str()));
        let auth = req.headers().get("x-aws-proxy-auth").expect("the endpoint token");
        assert!(auth.is_sensitive() && auth.to_str().unwrap() == "endpoint-token-for-seed");
        assert_eq!(req.headers().get("x-aws-proxy-port").map(|v| v.to_str().unwrap()), Some("9418"));
        assert!(req.headers().get(reqwest::header::AUTHORIZATION).is_none() && req.body().is_none(), "no bearer, no body: {:?}", req.headers());
        assert_eq!(req.headers().get(reqwest::header::CONTENT_LENGTH).map(|v| v.to_str().unwrap()), Some("0"), "the empty body is said: {:?}", req.headers());
        assert_eq!(req.timeout(), Some(&crate::bridge::vm::health::REQUEST_TIMEOUT));
    }

    /// A live run's note never carries the knob's mark (its row may decide the newest dns-path verdict); a knob run's
    /// always does (its row never decides it).
    #[test]
    fn only_a_knob_transcript_marks_the_dns_path_note() {
        let live = dns_path_note("resolves=no", "0123456789abcdef", "microvm-x", false);
        let knob = dns_path_note("resolves=no", "0123456789abcdef", "microvm-x", true);
        assert!(!live.contains(FAKE_SHELL_NOTE) && knob.ends_with(FAKE_SHELL_NOTE), "{live}\n{knob}");
        assert_eq!(live, "resolves=no; asked d0123456789abcdef.example.com A, and example.com A of each server that replied (microvm-x)");
    }

    /// A shim that completes the 101 and then never sends `hello_ok` must not
    /// hang the probe: `open_hello` bounds the wait for the answer (without
    /// the bound the terminate guard could not run until the VM's max
    /// duration). The server here upgrades and stays silent.
    #[tokio::test]
    async fn open_hello_is_bounded_when_hello_ok_never_arrives() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _ = ws.next().await; // read the hello, answer nothing
            tokio::time::sleep(Duration::from_secs(20)).await;
        });
        let target = AgentTarget {
            vm_id: "microvm-stall".into(),
            endpoint: "bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws".into(),
            session_token: Secret::new("session-token-for-open-hello".into()),
            vpc: false,
            shell: false,
        };
        let dial = AgentDial { local: Some(addr) };
        let token = Secret::new("endpoint-token-for-open-hello".into());
        // The outer 5 s timeout fails the test if open_hello itself did not return.
        let r = tokio::time::timeout(Duration::from_secs(5), open_hello(&dial, &target, &token, vec![], Some(3600), Duration::from_millis(150))).await;
        let Ok(inner) = r else { panic!("open_hello did not return within 5 s — the hello was not bounded") };
        match inner {
            Err(BridgeError::Transport(m)) => assert!(m.contains("no hello_ok from microvm-stall"), "{m}"),
            Err(e) => panic!("expected a bounded transport error, got {e}"),
            Ok(_) => panic!("open_hello unexpectedly completed hello against a silent server"),
        }
        task.abort();
    }

    /// The close-before-lookup trick must be a loop (critic M6a): a single
    /// send-and-close usually loses the race, so the orphan/inode-0 path is
    /// never exercised.
    #[test]
    fn the_close_before_lookup_trick_loops() {
        let script = firewall_agent_script();
        let before = script.split("@@orphan").next().expect("the orphan marker is present");
        let loop_at = before.rfind("while").expect("a loop before the orphan marker");
        assert!(before[loop_at..].contains("/dev/tcp/127.0.0.1/9000"), "the orphan send must sit inside the loop: {}", &before[loop_at..]);
    }

    /// The `--shell` VM carries SHELL_INGRESS but no egress qualifier: the
    /// shell token needs SHELL_INGRESS, not a vpc connector, and forcing vpc
    /// skipped the whole `--shell` measurement when none was configured.
    #[test]
    fn the_firewall_shell_vm_uses_the_default_egress() {
        let sf = firewall_shell_flags();
        assert!(sf.shell, "the --shell VM must pass SHELL_INGRESS");
        assert!(sf.egress.is_none(), "no egress qualifier: the default egress applies, as for the default VM");
    }
}
