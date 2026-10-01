//! The live platform probes `ai-env lab run` drives (plan S4 §8): each starts
//! its own short VMs (max duration 900 s, audited internet egress, label
//! `probe:<name>`), measures, and terminates every VM it started on every
//! path — success, failure or error — before the verdict is recorded.
use crate::bridge::api::{EndpointClient, IdleSpec, MicrovmApi, VmInfo, VmState, APP_PORT};
use crate::bridge::awscli;
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::ShellAuth;
use crate::bridge::vm::cmd::Ctx;
use crate::bridge::vm::{health, run, shell};
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

/// Run the live probe `name`; `arg` is its positional argument (the
/// connector ARN of `connector-pending`, already validated by `lab run`).
pub async fn run_probe<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, name: &str, arg: Option<&str>) -> Result<ProbeOutcome, BridgeError> {
    let mut started: Vec<String> = Vec::new();
    let result = match name {
        "payload-size" => payload_size(ctx, api, ep, &mut started).await,
        "no-traffic-before-run" => no_traffic_before_run(ctx, api, ep, &mut started).await,
        "snapshot-uniqueness" => snapshot_uniqueness(ctx, api, ep, &mut started).await,
        "idle-policy-limits" => idle_policy_limits(ctx, api, ep, &mut started).await,
        "connector-pending" => connector_pending(ctx, api, ep, arg, &mut started).await,
        "dns-path" => dns_path(ctx, api, ep, &mut started).await,
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
        match run::adopt_after_ambiguous_for(api, ep, &ctx.paths, pending, since, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms), "probe").await {
            Ok(run::Adoption::Adopted(id)) => started.push(id),
            // The egress gate could not terminate the run's VM: the terminate guard tries again.
            Err(BridgeError::EgressMismatch(m)) if !m.terminated => started.push(m.id.clone()),
            _ => {}
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
async fn connector_pending<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, arn: Option<&str>, started: &mut Vec<String>) -> Result<ProbeOutcome, BridgeError> {
    let arn = arn.map(str::trim).filter(|a| crate::bridge::config::is_connector_arn(a)).ok_or_else(|| BridgeError::Config("connector-pending needs the ARN of a connector that is not ACTIVE yet".into()))?;
    awscli::require_operator_account(arn).map_err(|e| BridgeError::Config(format!("connector-pending: {e}")))?;
    let (state, before) = connector_state(arn).map_err(|message| BridgeError::Sdk { op: "get_network_connector", message })?;
    if state != "PENDING" {
        return Err(BridgeError::Config(format!(
            "connector-pending: {arn} is {before}, not PENDING: nothing recorded (the probe measures RunMicrovm against a connector that is not ACTIVE yet; make connector-probe CONFIRM=create-probe-connector creates a fresh one)"
        )));
    }
    // Planned as internet (no configured connector needed), then given exactly the probe's connector.
    let mut f = flags("connector-pending", None, None, false);
    f.egress = Some(run::Egress::Internet);
    let mut p = plan(ctx, &f)?;
    p.egress = run::Egress::Vpc;
    p.egress_connectors = vec![arn.to_string()];
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

/// dns-path (S5): from a `--egress vpc --shell` VM, which DNS server (if any)
/// answers: `no-dns`; `platform-dns:<nameserver>` (a platform resolver
/// answered without resolving: DNS Firewall); `platform-dns-resolves:
/// <nameserver>` (a platform resolver resolved names: a failing verdict);
/// `open-dns:<nameserver>` (a public one, or any other, replied: a failing
/// verdict). Once the VM's `/health` answered, through the scripted shell:
/// `/etc/resolv.conf`'s nameserver, 1.1.1.1 (and OpenDNS on UDP 443), the
/// link-local resolver (169.254.169.253, `fd00:ec2::253`), the VPC's and the
/// VM subnet's +2 are asked for a well-known name over UDP and TCP, between
/// two `allowed` cases through the proxy that must both answer 401 (a VM
/// without working networking would read as `no-dns`); the note carries
/// `resolves=yes|no` and the resolv.conf nameserver
/// (`egress::check::dns_path_outcome`). Under the file-backed fake it
/// refuses (exit 9) after starting its VM and before any shell token or
/// dial; the terminate guard ends the VM.
async fn dns_path<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Vec<String>) -> Result<ProbeOutcome, BridgeError> {
    use crate::bridge::egress::check;
    if ctx.cfg.aws.egress_connector_arn.as_deref().is_none_or(|a| a.trim().is_empty()) {
        return Err(BridgeError::Config("dns-path needs [aws].egress_connector_arn (a vpc VM): run `make infra-status WRITE=1`".into()));
    }
    let mut f = flags("dns-path", None, None, true);
    f.egress = Some(run::Egress::Vpc);
    f.shell = true;
    let p = plan(ctx, &f)?;
    let vm = start(ctx, api, ep, &p, started).await?;
    health::read_health(api, ep, &ctx.paths, &vm.id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
    if ctx.knobs.fake_api.is_some() {
        return Err(shell::fake_backend_refusal("dns-path"));
    }
    let nonce = check::new_nonce();
    let script = check::render_dns_script(&nonce, &check::proxy_ip(&ctx.cfg, &ctx.paths));
    let output = shell::run_script(api, &vm.id, &script, check::script_budget(check::DNS_PATH_CASES.len()), ShellAuth::Header).await?;
    let markers = check::parse_markers(&output, &nonce).map_err(|e| BridgeError::Protocol(format!("dns-path: the shell transcript: {e}")))?;
    let (verdict, note) = check::dns_path_outcome(&markers).map_err(|message| BridgeError::Sdk { op: "probe", message: format!("dns-path on {}: {message}", vm.id) })?;
    Ok(ProbeOutcome { verdict, note: format!("{note} ({})", vm.id), image_version: Some(vm.image_version.clone()), ..ProbeOutcome::default() })
}
