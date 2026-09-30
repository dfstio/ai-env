//! `lab/probes.jsonl`: one version-stamped verdict per line (plan §7). S1
//! records the extension probes (`ai-env wrapper census --record-probes`), S3
//! the image-version probe (`ai-env infra versions-diff --record-probe`), S4
//! the platform probes (`ai-env lab run …`). Every writer appends through
//! [`append_row`] (one `write` per row on the 0600 `O_APPEND` file), so rows
//! from different commands never interleave.
use crate::bridge::census::read_rows;
use crate::bridge::logging::open_log_file;
use crate::errors::{CliError, Result};
use crate::outln;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

/// One line of `lab/probes.jsonl`. The four trailing fields arrived with S4;
/// they are omitted when unset, so S1/S3 rows keep their exact shape and old
/// rows still parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRow {
    /// The probe name (`entrypoint`, `image-version-delete`, `hooks-port`, …).
    pub probe: String,
    /// The stage that recorded the row (`S1`, `S3`, `S4`).
    pub stage: String,
    /// The extension bundle version (S1), or the image's claude version (S3/S4) when known.
    pub ext: Option<String>,
    /// `CLAUDE_AGENT_SDK_VERSION` of the session, when recorded (S1).
    pub sdk: Option<String>,
    /// What was observed.
    pub verdict: String,
    /// The rendered expectation: a literal verdict, `any-of:a|b|c`, or
    /// `recorded` (see [`expectation_holds`]).
    pub expected: String,
    /// RFC 3339 seconds, when the verdict was derived.
    pub ts: String,
    /// The image version the probe ran against (S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_version: Option<String>,
    /// The shim version `/health` reported (S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    /// The claude version `/health` reported (S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude: Option<String>,
    /// Free text: what the verdict was derived from, VM ids, a manual note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ProbeRow {
    /// A row stamped now, without the S4 fields.
    #[must_use]
    pub fn new(probe: &str, stage: &str, verdict: &str, expected: &Expectation) -> ProbeRow {
        ProbeRow {
            probe: probe.to_string(),
            stage: stage.to_string(),
            ext: None,
            sdk: None,
            verdict: verdict.to_string(),
            expected: expected.render(),
            ts: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
            image_version: None,
            shim: None,
            claude: None,
            note: None,
        }
    }
}

/// What a probe expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expectation {
    /// Exactly this verdict.
    Exact(String),
    /// One of these verdicts.
    AnyOf(Vec<String>),
    /// Anything: the row records a measurement.
    Recorded,
}

impl Expectation {
    /// The `expected` field: the literal, `any-of:a|b`, or `recorded`.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Expectation::Exact(v) => v.clone(),
            Expectation::AnyOf(vs) => format!("any-of:{}", vs.join("|")),
            Expectation::Recorded => "recorded".to_string(),
        }
    }
}

/// Does `verdict` satisfy the rendered expectation `expected`?
#[must_use]
pub fn expectation_holds(expected: &str, verdict: &str) -> bool {
    if expected == "recorded" {
        return true;
    }
    match expected.strip_prefix("any-of:") {
        Some(list) => list.split('|').any(|v| v == verdict),
        None => expected == verdict,
    }
}

/// The last recorded row of `probe` in `path` (as JSON), if any.
pub fn last_row(path: &Path, probe: &str) -> Result<Option<serde_json::Value>> {
    Ok(read_rows(path, None)?.into_iter().rev().find(|r| r.get("probe").and_then(|p| p.as_str()) == Some(probe)))
}

/// Append `row` to `path` with one `write` (0700 dir, 0600 file, `O_APPEND`,
/// `O_NOFOLLOW`), printing `probe X: old -> new` first when the last recorded
/// verdict of that probe differs. A short write is an error, never completed
/// by a second write. Returns whether the verdict satisfies the row's
/// expectation; callers decide whether that fails the command (after writing).
pub fn append_row(path: &Path, row: &ProbeRow) -> Result<bool> {
    if let Some(old) = last_row(path, &row.probe)?.as_ref().and_then(|r| r.get("verdict")).and_then(|v| v.as_str()) {
        if old != row.verdict {
            outln!("probe {}: {old} -> {}", row.probe, row.verdict);
        }
    }
    let mut line = serde_json::to_vec(row).map_err(|e| CliError::Msg(format!("probe row: {e}")))?;
    line.push(b'\n');
    let mut file = open_log_file(path)?;
    let written = file.write(&line)?;
    if written != line.len() {
        return Err(CliError::Msg(format!("short probe write: {written} of {} bytes to {}", line.len(), path.display())));
    }
    Ok(expectation_holds(&row.expected, &row.verdict))
}

// ---- the catalog (`ai-env lab list`) ---------------------------------------------------

/// Where a probe's verdict comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The wrapper's invocation census (S1).
    Census,
    /// Snapshots around `make deploy` (S3).
    Deploy,
    /// The image's runtime log (`make logs`), passed with `--log FILE`.
    Log,
    /// VMs started by the probe itself (runtime key, one Touch ID).
    Live,
    /// The operator's own `aws` CLI identity (CloudTrail).
    AwsCli,
    /// A live pass, then a `--log FILE` pass that pairs the run reports.
    LiveThenLog,
}

impl Source {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Source::Census => "census",
            Source::Deploy => "deploy",
            Source::Log => "log",
            Source::Live => "live",
            Source::AwsCli => "aws-cli",
            Source::LiveThenLog => "live+log",
        }
    }
}

/// A static expectation (the catalog's form of [`Expectation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Exact(&'static str),
    AnyOf(&'static [&'static str]),
    Recorded,
}

impl Expect {
    #[must_use]
    pub fn expectation(self) -> Expectation {
        match self {
            Expect::Exact(v) => Expectation::Exact(v.to_string()),
            Expect::AnyOf(vs) => Expectation::AnyOf(vs.iter().map(|v| (*v).to_string()).collect()),
            Expect::Recorded => Expectation::Recorded,
        }
    }
}

/// One known probe.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub name: &'static str,
    pub stage: &'static str,
    pub source: Source,
    pub expect: Expect,
    /// The command that records it.
    pub recorded_by: &'static str,
    /// What it answers.
    pub what: &'static str,
}

/// Every probe the stages record (plan §7), S1 and S3 included so `lab list`
/// shows the whole picture.
pub const CATALOG: [ProbeSpec; 12] = [
    ProbeSpec { name: "entrypoint", stage: "S1", source: Source::Census, expect: Expect::Exact("claude-vscode"), recorded_by: "ai-env wrapper census --record-probes", what: "CLAUDE_CODE_ENTRYPOINT the extension sets for the wrapper" },
    ProbeSpec { name: "stock-ext-oauth", stage: "S1", source: Source::Census, expect: Expect::Exact("absent"), recorded_by: "ai-env wrapper census --record-probes", what: "whether the stock extension advertises OAuth refresh" },
    ProbeSpec { name: "image-version-delete", stage: "S3", source: Source::Deploy, expect: Expect::Exact("kept"), recorded_by: "make deploy RECORD_PROBE=1", what: "whether an image update deletes earlier versions" },
    ProbeSpec { name: "hooks-port", stage: "S4", source: Source::Log, expect: Expect::Exact("9000"), recorded_by: "ai-env lab run hooks-port --log FILE", what: "the local port runtime hooks arrive on (= the configured hooks.port)" },
    ProbeSpec { name: "hooks-source-ip", stage: "S4", source: Source::Log, expect: Expect::Exact("loopback"), recorded_by: "ai-env lab run hooks-source-ip --log FILE", what: "where runtime hooks come from" },
    ProbeSpec { name: "payload-size", stage: "S4", source: Source::Live, expect: Expect::Exact("4096=accepted 4097=rejected"), recorded_by: "ai-env lab run payload-size", what: "the service's run-hook payload limit" },
    // Recorded, not expected: the AWS docs promise no traffic before /run, but the live endpoint forwarded a /health
    // while the control plane still said PENDING (30 Sep 2026); it is a race, so the shim must refuse everything but
    // /health until /run (a hello without the run's commitment already fails).
    ProbeSpec { name: "no-traffic-before-run", stage: "S4", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run no-traffic-before-run", what: "whether the endpoint forwards anything before /run returned, and for how long" },
    ProbeSpec { name: "runtime-env", stage: "S4", source: Source::Log, expect: Expect::Recorded, recorded_by: "ai-env lab run runtime-env --log FILE", what: "PID 1's environment in a MicroVM (names; credential variables)" },
    ProbeSpec { name: "cloudtrail-payload", stage: "S4", source: Source::AwsCli, expect: Expect::AnyOf(&["not-logged", "hidden", "absent", "commitment-only"]), recorded_by: "ai-env lab run cloudtrail-payload ID [--log FILE]", what: "what CloudTrail keeps of a run-hook payload (RunMicrovm is a data event, off by default)" },
    ProbeSpec { name: "disk-budget", stage: "S4", source: Source::Log, expect: Expect::Recorded, recorded_by: "ai-env lab run disk-budget --log FILE", what: "disk used by the image in a fresh VM" },
    ProbeSpec { name: "snapshot-uniqueness", stage: "S4", source: Source::LiveThenLog, expect: Expect::Exact("nonce-differs"), recorded_by: "ai-env lab run snapshot-uniqueness [--log FILE]", what: "per-VM boot nonces (boot_id is shared by snapshot clones)" },
    ProbeSpec { name: "idle-policy-limits", stage: "S4", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run idle-policy-limits", what: "which suspended durations the service accepts" },
];

/// The catalog entry of `name`.
#[must_use]
pub fn spec(name: &str) -> Option<&'static ProbeSpec> {
    CATALOG.iter().find(|p| p.name == name)
}

/// A row for `spec` stamped now, with the image's claude version and active
/// image version from `state/infra.toml` when recorded (live probes
/// overwrite them with what `/health` and the VM row say).
#[must_use]
pub fn stamped(paths: &crate::bridge::config::Paths, spec: &ProbeSpec, verdict: &str, note: Option<String>) -> ProbeRow {
    let infra = crate::bridge::infra::read_infra_state(paths).ok().flatten();
    let claude = infra.as_ref().and_then(|s| s.claude_version.clone());
    ProbeRow {
        ext: claude.clone(),
        claude,
        image_version: infra.and_then(|s| s.latest_active_image_version),
        note,
        ..ProbeRow::new(spec.name, spec.stage, verdict, &spec.expect.expectation())
    }
}

/// Append `row`, audit it (`lab_probe`, plan S4 D24), print `recorded X=V
/// (expected E)`, and fail (after writing) when the verdict misses its
/// expectation.
pub fn record(paths: &crate::bridge::config::Paths, row: &ProbeRow) -> Result<()> {
    let holds = append_row(&paths.probes(), row)?;
    let detail = crate::bridge::audit::detail(&[("actor", "cli".into()), ("probe", row.probe.clone()), ("verdict", row.verdict.clone()), ("expected", row.expected.clone())]);
    if let Err(e) = crate::bridge::audit::append(&paths.audit(), &crate::bridge::audit::AuditRow::new("lab_probe", None, detail)) {
        eprintln!("ai-env: warning: audit row lab_probe not written: {e}");
    }
    outln!("recorded {}={} (expected {})", row.probe, row.verdict, row.expected);
    if let Some(note) = &row.note {
        outln!("  {note}");
    }
    if !holds {
        crate::bail!("probe verdict differs from the expectation: {}={} (expected {})", row.probe, row.verdict, row.expected);
    }
    Ok(())
}

// ---- log parsers ------------------------------------------------------------------------

/// One `ai-env: hook <name> peer=… local=… origin=… len=… status=… ms=…`
/// line of the shim (`shim/hooks.rs`), found anywhere in a log line (the
/// `make logs` output prefixes a timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookLine {
    pub hook: String,
    pub peer: Option<String>,
    pub local: Option<String>,
    pub origin: Option<String>,
    pub status: Option<u16>,
}

/// Every hook line in `text`.
#[must_use]
pub fn parse_hook_lines(text: &str) -> Vec<HookLine> {
    const MARK: &str = "ai-env: hook ";
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(at) = line.find(MARK) else { continue };
        let mut words = line[at + MARK.len()..].split_whitespace();
        let Some(hook) = words.next() else { continue };
        let mut h = HookLine { hook: hook.to_string(), peer: None, local: None, origin: None, status: None };
        for w in words {
            let Some((k, v)) = w.split_once('=') else { continue };
            let v = (v != "-").then(|| v.to_string());
            match k {
                "peer" => h.peer = v,
                "local" => h.local = v,
                "origin" => h.origin = v,
                "status" => h.status = v.and_then(|s| s.parse().ok()),
                _ => {}
            }
        }
        out.push(h);
    }
    out
}

/// The port of `host:port` / `[v6]:port`.
#[must_use]
pub fn local_port(addr: &str) -> Option<u16> {
    addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

/// The runtime hooks (the image hooks `/ready` and `/validate` come from the build).
const RUNTIME_HOOKS: [&str; 4] = ["run", "resume", "suspend", "terminate"];

fn runtime_hooks(lines: &[HookLine]) -> Vec<&HookLine> {
    lines.iter().filter(|h| RUNTIME_HOOKS.contains(&h.hook.as_str())).collect()
}

fn joined<'a>(it: impl Iterator<Item = &'a str>) -> String {
    let set: std::collections::BTreeSet<&str> = it.collect();
    set.into_iter().collect::<Vec<_>>().join(",")
}

fn counts(lines: &[&HookLine]) -> String {
    let mut by: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for h in lines {
        *by.entry(h.hook.as_str()).or_default() += 1;
    }
    by.iter().map(|(k, v)| format!("{k}×{v}")).collect::<Vec<_>>().join(" ")
}

/// hooks-port: the set of local ports of the runtime hook lines (`9000`, or
/// `8080,9000` when they differ); `Err` when the log has none.
pub fn verdict_hooks_port(lines: &[HookLine]) -> std::result::Result<(String, String), String> {
    let rt = runtime_hooks(lines);
    if rt.is_empty() {
        return Err("no runtime hook line (run/resume/suspend/terminate) in the log".into());
    }
    let ports: Vec<String> = rt.iter().filter_map(|h| h.local.as_deref().and_then(local_port)).map(|p| p.to_string()).collect();
    if ports.is_empty() {
        return Err("the runtime hook lines carry no local address".into());
    }
    Ok((joined(ports.iter().map(String::as_str)), format!("{} runtime hook lines: {}", rt.len(), counts(&rt))))
}

/// hooks-source-ip: the set of origins of the runtime hook lines
/// (`loopback`, `remote`, `self`, joined when mixed).
pub fn verdict_hooks_source(lines: &[HookLine]) -> std::result::Result<(String, String), String> {
    let rt = runtime_hooks(lines);
    if rt.is_empty() {
        return Err("no runtime hook line (run/resume/suspend/terminate) in the log".into());
    }
    let origins: Vec<&str> = rt.iter().filter_map(|h| h.origin.as_deref()).collect();
    if origins.is_empty() {
        return Err("the runtime hook lines carry no origin".into());
    }
    let peers = joined(rt.iter().filter_map(|h| h.peer.as_deref().and_then(|p| p.rsplit_once(':').map(|(ip, _)| ip))));
    Ok((joined(origins.into_iter()), format!("{} runtime hook lines: {}; peers {peers}", rt.len(), counts(&rt))))
}

/// Every `ai-env: run-report {json}` object in `text` (plan S4 D19).
#[must_use]
pub fn parse_run_reports(text: &str) -> Vec<serde_json::Value> {
    const MARK: &str = "ai-env: run-report ";
    text.lines().filter_map(|l| l.find(MARK).map(|at| &l[at + MARK.len()..])).filter_map(|j| serde_json::from_str::<serde_json::Value>(j.trim()).ok()).filter(serde_json::Value::is_object).collect()
}

fn reports_of<'a>(reports: &'a [serde_json::Value], hook: &str) -> Vec<&'a serde_json::Value> {
    reports.iter().filter(|r| r.get("hook").and_then(|h| h.as_str()) == Some(hook)).collect()
}

/// The environment values the run report may carry (the shim's allowlist, D19).
const RUNTIME_ENV_VALUES: [&str; 6] = ["HOME", "PATH", "AWS_REGION", "AWS_LAMBDA_MICROVM_IMAGE_NAME", "AWS_LAMBDA_MICROVM_IMAGE_ARN", "AWS_LAMBDA_MICROVM_IMAGE_VERSION"];

const NO_REPORT: &str = "no `ai-env: run-report` line with hook \"run\" in the log (runtime logs need [aws].execution_role_arn and an image built from S4 on)";

/// runtime-env from the newest `run` report: the verdict says whether AWS
/// credential variables were in PID 1's environment (names only ever), the
/// note lists every name and the allowlisted values. The shim writes
/// `env` and `aws_credential_env` as null when PID 1's environ was
/// unreadable: that is an error here, never `absent`.
pub fn verdict_runtime_env(reports: &[serde_json::Value]) -> std::result::Result<(String, String), String> {
    fn strs(v: &serde_json::Value) -> Vec<&str> {
        v.as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect()).unwrap_or_default()
    }
    let r = *reports_of(reports, "run").last().ok_or(NO_REPORT)?;
    if r.get("unsupported").is_some() {
        return Err("the run report says unsupported (not a Linux shim)".into());
    }
    let env = r.get("env").filter(|e| e.is_object());
    let cred = r.get("aws_credential_env").or_else(|| r.pointer("/env/aws_credential_env")).filter(|c| c.is_array());
    let (Some(env), Some(cred)) = (env, cred) else {
        return Err("the run report has no environment (PID 1's environ was unreadable)".into());
    };
    let cred = strs(cred);
    let names = env.get("names").map(strs).unwrap_or_default();
    // Only the shim's allowlisted values are ever repeated (defence in depth against a shim that sent more).
    let values = env
        .get("values")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().filter(|(k, _)| RUNTIME_ENV_VALUES.contains(&k.as_str())).map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("?"))).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let verdict = if cred.is_empty() { "aws-credentials:absent".to_string() } else { format!("aws-credentials:{}", cred.join(",")) };
    Ok((verdict, format!("names: {}; values: {values}", names.join(","))))
}

/// disk-budget from the newest `run` report: `used=<MiB>MiB total=<MiB>MiB`
/// (a note warns above 512 MiB, the plan's budget for the bare image).
pub fn verdict_disk_budget(reports: &[serde_json::Value]) -> std::result::Result<(String, String), String> {
    let r = *reports_of(reports, "run").last().ok_or(NO_REPORT)?;
    let n = |k: &str| r.get(k).and_then(serde_json::Value::as_u64);
    let (Some(used), Some(total)) = (n("disk_used_bytes"), n("disk_total_bytes")) else {
        return Err("the run report has no disk_used_bytes/disk_total_bytes".into());
    };
    let mib = |b: u64| b / (1024 * 1024);
    let note = if mib(used) > 512 { "above the 0.5 GB budget".to_string() } else { "within the 0.5 GB budget".to_string() };
    Ok((format!("used={}MiB total={}MiB", mib(used), mib(total)), note))
}

/// snapshot-uniqueness, log pass: the `boot_id`s of the `run` reports of
/// `ids` (the VMs of the live pass). Returns `identical` / `differ` and the pairs.
pub fn boot_ids(reports: &[serde_json::Value], ids: &[&str]) -> std::result::Result<(String, String), String> {
    let mut pairs = Vec::new();
    for id in ids {
        let r = reports_of(reports, "run").into_iter().rev().find(|r| r.get("microvm_id").and_then(|m| m.as_str()) == Some(*id)).ok_or_else(|| format!("no run report of {id} in the log"))?;
        let boot = r.get("boot_id").and_then(|b| b.as_str()).ok_or_else(|| format!("the run report of {id} has no boot_id"))?;
        pairs.push((*id, boot.to_string()));
    }
    let same = pairs.windows(2).all(|w| w[0].1 == w[1].1);
    let listed = pairs.iter().map(|(id, b)| format!("{id}={b}")).collect::<Vec<_>>().join(" ");
    Ok((if same { "identical" } else { "differ" }.to_string(), listed))
}

// ---- CloudTrail ---------------------------------------------------------------------------

/// The CloudTrail resource type of Lambda MicroVMs data events. RunMicrovm,
/// TerminateMicrovm, SuspendMicrovm, ResumeMicrovm and the two token calls
/// are data events: CloudTrail logs them only for a trail or event data store
/// that selects this type, and event history (`lookup-events`) never has
/// them (AWS Lambda MicroVMs docs, "Monitoring"; S4 part B, 30 Sep 2026).
pub const MICROVM_DATA_RESOURCE: &str = "AWS::Lambda::MicrovmImage";

/// Whether one field selector of an advanced event selector lets `value`
/// through, as CloudTrail evaluates it ("How CloudTrail evaluates multiple
/// conditions for a field"): the SELECT operators (`Equals`, `StartsWith`,
/// `EndsWith`) are OR'd — any match selects, and a field without one selects
/// everything — and a match of any DESELECT operator (`NotEquals`,
/// `NotStartsWith`, `NotEndsWith`) excludes.
fn field_allows(field: &serde_json::Value, value: &str) -> bool {
    let list = |k: &str| field.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>());
    let any = |k: &str, f: &dyn Fn(&str) -> bool| list(k).is_some_and(|l| l.iter().any(|x| f(x)));
    let has_select = ["Equals", "StartsWith", "EndsWith"].iter().any(|k| list(k).is_some());
    let selected = !has_select || any("Equals", &|x| x == value) || any("StartsWith", &|x| value.starts_with(x)) || any("EndsWith", &|x| value.ends_with(x));
    let deselected = any("NotEquals", &|x| x == value) || any("NotStartsWith", &|x| value.starts_with(x)) || any("NotEndsWith", &|x| value.ends_with(x));
    selected && !deselected
}

/// Whether a `get-event-selectors` (trail) or `get-event-data-store`
/// document selects the RunMicrovm data event. Conservative: a field the
/// selector does not constrain lets the event through, and only the fields
/// that can exclude RunMicrovm are evaluated (`resources.ARN` is not), so a
/// "maybe" counts as logging — the probe then asks for the trail's record
/// instead of claiming nothing is kept.
#[must_use]
pub fn selectors_log_microvm_data(doc: &serde_json::Value) -> bool {
    let run_microvm = [("eventCategory", "Data"), ("resources.type", MICROVM_DATA_RESOURCE), ("eventName", "RunMicrovm"), ("eventSource", "lambda.amazonaws.com"), ("readOnly", "false")];
    let advanced = doc.get("AdvancedEventSelectors").and_then(|a| a.as_array()).is_some_and(|sels| {
        sels.iter().any(|sel| {
            let fields = sel.get("FieldSelectors").and_then(|f| f.as_array()).map(Vec::as_slice).unwrap_or_default();
            run_microvm.iter().all(|(name, value)| fields.iter().filter(|f| f.get("Field").and_then(|v| v.as_str()) == Some(*name)).all(|f| field_allows(f, value)))
        })
    });
    let basic = doc.get("EventSelectors").and_then(|a| a.as_array()).is_some_and(|sels| {
        sels.iter().any(|sel| {
            let rw_ok = sel.get("ReadWriteType").and_then(|v| v.as_str()) != Some("ReadOnly");
            rw_ok && sel.get("DataResources").and_then(|d| d.as_array()).is_some_and(|d| d.iter().any(|r| r.get("Type").and_then(|t| t.as_str()) == Some(MICROVM_DATA_RESOURCE)))
        })
    });
    advanced || basic
}

/// The columns a CloudTrail Lake query must select (aliased as named) for
/// `--log`: the record's fields as plain strings, plus the two maps whole so
/// the session-token search sees everything.
pub const LAKE_COLUMNS: &str = "eventID, eventName, element_at(requestParameters, 'clientToken') AS clientToken, element_at(requestParameters, 'runHookPayload') AS runHookPayload, element_at(responseElements, 'microvmId') AS microvmId, requestParameters, responseElements";

/// The CloudTrail records in `doc`, each with its raw text (searched for the
/// session token): a trail's log file (`{"Records": [...]}`, gunzipped), a
/// `lookup-events` answer (`{"Events": [{"CloudTrailEvent": "..."}]}`), a
/// CloudTrail Lake `get-query-results` answer over [`LAKE_COLUMNS`]
/// (`{"QueryResultRows": [[{"eventName": "..."}, ...]]}`), a JSON array of
/// records, or one record.
fn cloudtrail_records(doc: &serde_json::Value) -> std::result::Result<Vec<(serde_json::Value, String)>, String> {
    let own = |r: &serde_json::Value| (r.clone(), r.to_string());
    if let Some(records) = doc.get("Records").and_then(|r| r.as_array()) {
        return Ok(records.iter().map(own).collect());
    }
    if let Some(rows) = doc.get("QueryResultRows").and_then(|r| r.as_array()) {
        let mut out = Vec::new();
        for row in rows {
            // Each row is a list of one-column maps.
            let mut cols = serde_json::Map::new();
            for cell in row.as_array().map(Vec::as_slice).unwrap_or_default() {
                if let Some(o) = cell.as_object() {
                    cols.extend(o.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            }
            // A column that was not selected cannot be told from an absent field: refuse rather than guess.
            if let Some(missing) = ["eventName", "microvmId", "clientToken", "runHookPayload"].iter().find(|c| !cols.contains_key(**c)) {
                return Err(format!("a CloudTrail Lake row without the column {missing}: select {LAKE_COLUMNS}"));
            }
            let col = |k: &str| cols.get(k).cloned().filter(|v| !v.as_str().is_some_and(str::is_empty)).unwrap_or(serde_json::Value::Null);
            let rec = serde_json::json!({
                "eventName": col("eventName"), "eventID": col("eventID"),
                "requestParameters": {"clientToken": col("clientToken"), "runHookPayload": col("runHookPayload")},
                "responseElements": {"microvmId": col("microvmId")},
            });
            out.push((rec, serde_json::Value::Object(cols).to_string()));
        }
        return Ok(out);
    }
    if let Some(events) = doc.get("Events").and_then(|e| e.as_array()) {
        return Ok(events
            .iter()
            .filter_map(|ev| ev.get("CloudTrailEvent").and_then(|c| c.as_str()))
            .filter_map(|raw| serde_json::from_str::<serde_json::Value>(raw).ok().map(|inner| (inner, raw.to_string())))
            .collect());
    }
    if let Some(records) = doc.as_array() {
        return Ok(records.iter().map(own).collect());
    }
    if doc.get("eventName").is_some() {
        return Ok(vec![own(doc)]);
    }
    Err("not a CloudTrail document: no Records, Events or eventName".into())
}

/// cloudtrail-payload from a CloudTrail document (see [`cloudtrail_records`]):
/// the `RunMicrovm` record of this VM (matched by `responseElements.microvmId`
/// or `requestParameters.clientToken`; records of other calls on the same VM
/// are skipped), then what it kept of `runHookPayload`: `absent`, `hidden` (a
/// redaction marker), `commitment-only` (the payload with the commitment and
/// without the session token), `present-other`, or `LEAKED` when the session
/// token appears anywhere in the record. `Ok(None)` when no record matched.
pub fn verdict_cloudtrail(doc_json: &str, id: &str, client_token: &str, session_token: Option<&str>, commit: &str) -> std::result::Result<Option<(String, String)>, String> {
    let doc: serde_json::Value = serde_json::from_str(doc_json).map_err(|e| format!("CloudTrail document: {e}"))?;
    for (inner, raw) in cloudtrail_records(&doc)? {
        if inner.get("eventName").and_then(|v| v.as_str()).is_some_and(|n| n != "RunMicrovm") {
            continue;
        }
        let raw = raw.as_str();
        let by_id = inner.pointer("/responseElements/microvmId").and_then(|v| v.as_str()) == Some(id);
        let by_token = !client_token.is_empty() && inner.pointer("/requestParameters/clientToken").and_then(|v| v.as_str()) == Some(client_token);
        if !(by_id || by_token) {
            continue;
        }
        let event_id = inner.get("eventID").and_then(|v| v.as_str()).unwrap_or("?");
        if session_token.is_some_and(|t| !t.is_empty() && raw.contains(t)) {
            return Ok(Some(("LEAKED".to_string(), format!("event {event_id}: the session token itself is in the event"))));
        }
        // A redaction marker is the whole value, never a substring (a logged payload's owner may say "hidden").
        let marker = |s: &str| {
            let s = s.trim();
            s.eq_ignore_ascii_case("HIDDEN_DUE_TO_SECURITY_REASONS") || s.eq_ignore_ascii_case("REDACTED") || s.eq_ignore_ascii_case("HIDDEN") || (!s.is_empty() && s.chars().all(|c| c == '*'))
        };
        let verdict = match inner.pointer("/requestParameters/runHookPayload") {
            None | Some(serde_json::Value::Null) => "absent",
            Some(serde_json::Value::String(s)) if marker(s) => "hidden",
            Some(serde_json::Value::String(s)) if s.contains(commit) => "commitment-only",
            Some(_) => "present-other",
        };
        return Ok(Some((verdict.to_string(), format!("event {event_id} (matched by {})", if by_id { "microvmId" } else { "clientToken" }))));
    }
    Ok(None)
}

// ---- `ai-env lab list|show` ---------------------------------------------------------------

/// `ai-env lab list [--json]`: every probe with its last recorded verdict.
pub fn cmd_list(json: bool) -> Result<()> {
    let paths = crate::bridge::config::Paths::resolve()?;
    let mut rows = Vec::new();
    for p in &CATALOG {
        let last = last_row(&paths.probes(), p.name)?;
        let field = |k: &str| last.as_ref().and_then(|r| r.get(k)).and_then(|v| v.as_str()).map(str::to_string);
        rows.push(serde_json::json!({
            "probe": p.name, "stage": p.stage, "source": p.source.name(), "expected": p.expect.expectation().render(),
            "last_verdict": field("verdict"), "last_ts": field("ts"), "recorded_by": p.recorded_by, "what": p.what,
        }));
    }
    if json {
        outln!("{}", serde_json::to_string_pretty(&rows).map_err(|e| CliError::Msg(e.to_string()))?);
        return Ok(());
    }
    for r in &rows {
        let s = |k: &str| r[k].as_str().unwrap_or("-").to_string();
        outln!("{:<22} {:<3} {:<9} {:<28} last {:<28} {}", s("probe"), s("stage"), s("source"), s("expected"), s("last_verdict"), s("recorded_by"));
    }
    Ok(())
}

/// `ai-env lab show PROBE [--json]`: the recorded rows of one probe, oldest first.
pub fn cmd_show(probe: &str, json: bool) -> Result<()> {
    if spec(probe).is_none() {
        return Err(CliError::Usage(format!("unknown probe {probe:?} (ai-env lab list)")));
    }
    let paths = crate::bridge::config::Paths::resolve()?;
    let rows: Vec<serde_json::Value> = read_rows(&paths.probes(), None)?.into_iter().filter(|r| r.get("probe").and_then(|p| p.as_str()) == Some(probe)).collect();
    if json {
        outln!("{}", serde_json::to_string_pretty(&rows).map_err(|e| CliError::Msg(e.to_string()))?);
    } else if rows.is_empty() {
        outln!("no rows recorded for {probe}");
    } else {
        for r in &rows {
            let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("-").to_string();
            outln!("{}  {}={}  (expected {})  {}", s("ts"), probe, s("verdict"), s("expected"), s("note"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expectations_render_and_hold() {
        let exact = Expectation::Exact("9000".into());
        let any = Expectation::AnyOf(vec!["hidden".into(), "absent".into()]);
        assert_eq!(exact.render(), "9000");
        assert_eq!(any.render(), "any-of:hidden|absent");
        assert_eq!(Expectation::Recorded.render(), "recorded");
        assert!(expectation_holds("9000", "9000"));
        assert!(!expectation_holds("9000", "8080"));
        assert!(expectation_holds("any-of:hidden|absent", "absent"));
        assert!(!expectation_holds("any-of:hidden|absent", "present"));
        assert!(expectation_holds("recorded", "anything at all"));
    }

    #[test]
    fn s1_rows_keep_their_shape_and_old_rows_parse() {
        let row = ProbeRow::new("entrypoint", "S1", "claude-vscode", &Expectation::Exact("claude-vscode".into()));
        let text = serde_json::to_string(&row).unwrap();
        for absent in ["image_version", "shim", "claude", "note"] {
            assert!(!text.contains(&format!("\"{absent}\":")), "{absent} must be omitted when unset: {text}");
        }
        let old = r#"{"probe":"entrypoint","stage":"S1","ext":"2.1.282","sdk":null,"verdict":"claude-vscode","expected":"claude-vscode","ts":"2026-09-23T10:00:00Z"}"#;
        let back: ProbeRow = serde_json::from_str(old).unwrap();
        assert_eq!(back.note, None);
        assert_eq!(back.ext.as_deref(), Some("2.1.282"));
    }

    #[test]
    fn catalog_names_are_unique_and_cover_the_nine_s4_probes() {
        let names: std::collections::BTreeSet<&str> = CATALOG.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), CATALOG.len());
        assert_eq!(CATALOG.iter().filter(|p| p.stage == "S4").count(), 9);
        assert_eq!(spec("cloudtrail-payload").unwrap().expect.expectation().render(), "any-of:not-logged|hidden|absent|commitment-only");
    }

    #[test]
    fn hook_lines_parse_the_shim_format_behind_a_timestamp() {
        let log = "2026-09-29T10:21:08 ai-env: hook ready peer=127.0.0.1:1 local=127.0.0.1:9000 origin=loopback len=- status=200 ms=1\n\
                   2026-09-29T10:21:09 ai-env: hook run peer=127.0.0.1:34567 local=127.0.0.1:9000 origin=loopback len=238 status=200 ms=190\n\
                   noise\n\
                   2026-09-29T10:22:00 ai-env: hook terminate peer=127.0.0.1:40000 local=127.0.0.1:9000 origin=loopback len=- status=200 ms=3\n";
        let lines = parse_hook_lines(log);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], HookLine { hook: "run".into(), peer: Some("127.0.0.1:34567".into()), local: Some("127.0.0.1:9000".into()), origin: Some("loopback".into()), status: Some(200) });
        assert_eq!(lines[2].peer.as_deref(), Some("127.0.0.1:40000"));
        let (port, note) = verdict_hooks_port(&lines).unwrap();
        assert_eq!(port, "9000");
        assert!(note.contains("run×1") && note.contains("terminate×1") && !note.contains("ready"), "{note}");
        assert_eq!(verdict_hooks_source(&lines).unwrap().0, "loopback");
        let mixed = parse_hook_lines("ai-env: hook run peer=10.0.0.9:1 local=10.0.0.5:8080 origin=remote\nai-env: hook resume peer=127.0.0.1:2 local=127.0.0.1:9000 origin=loopback");
        assert_eq!(verdict_hooks_port(&mixed).unwrap().0, "8080,9000");
        assert_eq!(verdict_hooks_source(&mixed).unwrap().0, "loopback,remote");
        assert!(verdict_hooks_port(&parse_hook_lines("ai-env: hook ready local=127.0.0.1:9000")).is_err(), "image hooks do not count");
        assert_eq!(local_port("[::1]:9000"), Some(9000));
    }

    #[test]
    fn run_reports_give_env_disk_and_boot_ids() {
        let secret_value = format!("{}{}", "AKIA", "Q".repeat(16));
        // The shim's shape: `aws_credential_env` at the top level, beside `env`.
        let r1 = serde_json::json!({"hook":"run","microvm_id":"microvm-a","boot_id":"b-1","disk_total_bytes": 8u64<<30, "disk_used_bytes": 300u64<<20,
            "env":{"names":["HOME","PATH"],"values":{"HOME":"/root"}},"aws_credential_env":[],"zombies":0});
        // A buggy shim that leaked a credential VALUE into `values` must not get it into the verdict or the note.
        let r2 = serde_json::json!({"hook":"run","microvm_id":"microvm-b","boot_id":"b-1","disk_total_bytes": 1, "disk_used_bytes": 1,
            "env":{"names":["AWS_ACCESS_KEY_ID"],"values":{"AWS_ACCESS_KEY_ID":secret_value,"HOME":"/root"}},"aws_credential_env":["AWS_ACCESS_KEY_ID"],"zombies":0});
        let unreadable = serde_json::json!({"hook":"run","microvm_id":"microvm-c","boot_id":"b-1","env":null,"aws_credential_env":null});
        assert!(verdict_runtime_env(&[unreadable]).unwrap_err().contains("unreadable"), "null env is never `absent`");
        let log = format!("t ai-env: run-report {r1}\nx\nt ai-env: run-report {{broken\nt ai-env: run-report {r2}\n");
        let reports = parse_run_reports(&log);
        assert_eq!(reports.len(), 2);
        let (v, note) = verdict_runtime_env(&reports).unwrap();
        assert_eq!(v, "aws-credentials:AWS_ACCESS_KEY_ID", "the newest run report");
        assert!(!note.contains(&secret_value) && !v.contains(&secret_value), "{note}");
        assert!(note.contains("HOME=/root"), "{note}");
        assert_eq!(verdict_runtime_env(&reports[..1]).unwrap().0, "aws-credentials:absent");
        assert_eq!(verdict_disk_budget(&reports[..1]).unwrap().0, "used=300MiB total=8192MiB");
        assert_eq!(boot_ids(&reports, &["microvm-a", "microvm-b"]).unwrap().0, "identical");
        assert!(boot_ids(&reports, &["microvm-c"]).is_err());
        assert!(verdict_disk_budget(&[]).unwrap_err().contains("execution_role_arn"));
    }

    #[test]
    fn cloudtrail_verdicts() {
        let token = "s".repeat(64);
        let commit = "c".repeat(64);
        let event = |params: serde_json::Value| {
            let inner = serde_json::json!({"eventID":"e1","requestParameters":params,"responseElements":{"microvmId":"microvm-a"}});
            serde_json::json!({"Events":[{"CloudTrailEvent": inner.to_string()}]}).to_string()
        };
        let v = |params: serde_json::Value| verdict_cloudtrail(&event(params), "microvm-a", "", Some(&token), &commit).unwrap().unwrap().0;
        assert_eq!(v(serde_json::json!({"imageIdentifier":"x"})), "absent");
        assert_eq!(v(serde_json::json!({"runHookPayload":"HIDDEN_DUE_TO_SECURITY_REASONS"})), "hidden");
        assert_eq!(v(serde_json::json!({"runHookPayload": format!("{{\"commit\":\"{commit}\"}}")})), "commitment-only");
        assert_eq!(v(serde_json::json!({"runHookPayload":"something else"})), "present-other");
        assert_eq!(v(serde_json::json!({"runHookPayload": format!("x{token}")})), "LEAKED");
        assert_eq!(verdict_cloudtrail(&event(serde_json::json!({})), "microvm-other", "", None, &commit).unwrap(), None, "not yet visible");
        assert!(verdict_cloudtrail("{}", "microvm-a", "", None, &commit).is_err());
        // A trail's log file: the Records of other calls on the same VM (TerminateMicrovm answers with its
        // microvmId too) must not stand in for RunMicrovm, whose record shape is the AWS docs example.
        let terminate = serde_json::json!({"eventName":"TerminateMicrovm","eventID":"e0","responseElements":{"microvmId":"microvm-a"}});
        let run = serde_json::json!({"eventName":"RunMicrovm","eventID":"e2","requestParameters":{"microvmImageArn":"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent"},
            "responseElements":{"microvmId":"microvm-a","microvmState":"PENDING"},"eventCategory":"Data","managementEvent":false});
        let file = |records: Vec<&serde_json::Value>| serde_json::json!({"Records": records}).to_string();
        assert_eq!(verdict_cloudtrail(&file(vec![&terminate]), "microvm-a", "", None, &commit).unwrap(), None, "only RunMicrovm counts");
        let (v, note) = verdict_cloudtrail(&file(vec![&terminate, &run]), "microvm-a", "", Some(&token), &commit).unwrap().unwrap();
        assert_eq!((v.as_str(), note.as_str()), ("absent", "event e2 (matched by microvmId)"));
        assert_eq!(verdict_cloudtrail(&run.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "absent", "one record");
        assert_eq!(verdict_cloudtrail(&serde_json::json!([run]).to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "absent", "an array");
        let leaked = serde_json::json!({"eventName":"RunMicrovm","responseElements":{"microvmId":"microvm-a"},"requestParameters":{"note":token}});
        assert_eq!(verdict_cloudtrail(&file(vec![&leaked]), "microvm-a", "", Some(&token), &commit).unwrap().unwrap().0, "LEAKED", "anywhere in the record");
    }

    #[test]
    fn microvm_data_event_selectors() {
        let field = |name: &str, op: &str, values: &[&str]| serde_json::json!({"Field": name, op: values});
        let adv = |fields: Vec<serde_json::Value>| serde_json::json!({"AdvancedEventSelectors": [{"Name": "s", "FieldSelectors": fields}]});
        // The AWS docs' selector for MicroVM data events.
        assert!(selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "Equals", &[MICROVM_DATA_RESOURCE])])));
        assert!(selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "StartsWith", &["AWS::Lambda::"])])));
        assert!(selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"])])), "an unconstrained type is a maybe: counts as logging");
        assert!(!selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Management"])])), "the default management selector");
        assert!(!selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "Equals", &["AWS::S3::Object"])])));
        assert!(!selectors_log_microvm_data(&adv(vec![
            field("eventCategory", "Equals", &["Data"]),
            field("resources.type", "Equals", &[MICROVM_DATA_RESOURCE]),
            field("eventName", "NotEquals", &["RunMicrovm"]),
        ])), "RunMicrovm filtered out");
        assert!(!selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "Equals", &[MICROVM_DATA_RESOURCE]), field("readOnly", "Equals", &["true"])])));
        let basic = |ty: &str, rw: &str| serde_json::json!({"EventSelectors": [{"ReadWriteType": rw, "IncludeManagementEvents": true, "DataResources": [{"Type": ty, "Values": ["arn:aws:lambda"]}]}]});
        assert!(selectors_log_microvm_data(&basic(MICROVM_DATA_RESOURCE, "All")));
        assert!(!selectors_log_microvm_data(&basic(MICROVM_DATA_RESOURCE, "ReadOnly")));
        assert!(!selectors_log_microvm_data(&basic("AWS::S3::Object", "All")));
        assert!(!selectors_log_microvm_data(&serde_json::json!({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": true, "DataResources": []}]})), "management events only");
        assert!(!selectors_log_microvm_data(&serde_json::json!({})));
    }

    #[test]
    fn field_selector_operators_follow_cloudtrail() {
        // CloudTrail: SELECT operators (Equals, StartsWith, EndsWith) are OR'd; any DESELECT match excludes.
        let data = |name: serde_json::Value| {
            let mut name = name;
            name["Field"] = serde_json::json!("eventName");
            serde_json::json!({"AdvancedEventSelectors": [{"FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}, name]}]})
        };
        let on = |name: serde_json::Value| selectors_log_microvm_data(&data(name));
        assert!(on(serde_json::json!({"Equals": ["RunMicrovm"], "StartsWith": ["CreateMicrovm"]})), "OR: Equals matches");
        assert!(on(serde_json::json!({"EndsWith": ["Microvm"], "StartsWith": ["Create"]})), "OR: EndsWith matches");
        assert!(on(serde_json::json!({"Equals": ["TerminateMicrovm"], "StartsWith": ["Run"]})), "OR: StartsWith matches");
        assert!(on(serde_json::json!({"EndsWith": ["Microvm"]})));
        assert!(!on(serde_json::json!({"EndsWith": ["Image"]})));
        assert!(!on(serde_json::json!({"StartsWith": ["Run"], "NotEquals": ["RunMicrovm"]})), "a DESELECT match wins");
        assert!(!on(serde_json::json!({"NotStartsWith": ["Run"]})));
        assert!(on(serde_json::json!({"NotStartsWith": ["Terminate"]})));
        assert!(!on(serde_json::json!({"NotEndsWith": ["Microvm"]})));
        assert!(on(serde_json::json!({"NotEndsWith": ["Image"]})));
        // eventSource: the service RunMicrovm is recorded under.
        let source = |v: &str| {
            selectors_log_microvm_data(&serde_json::json!({"AdvancedEventSelectors": [{"FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}, {"Field": "eventSource", "Equals": [v]}]}]}))
        };
        assert!(source("lambda.amazonaws.com"));
        assert!(!source("s3.amazonaws.com"));
        // The console's usual pair: a management selector, then the data selector — any selector may log it.
        let pair = serde_json::json!({"AdvancedEventSelectors": [
            {"Name": "Management events", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
            {"Name": "MicroVM", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}]}]});
        assert!(selectors_log_microvm_data(&pair));
    }

    #[test]
    fn cloudtrail_matches_by_client_token_reads_lake_rows_and_exact_markers() {
        let commit = "c".repeat(64);
        // No microvmId in the record: matched by clientToken.
        let by_token = serde_json::json!({"Records": [{"eventName": "RunMicrovm", "eventID": "e3", "requestParameters": {"clientToken": "ct-1", "runHookPayload": format!("{{\"commit\":\"{commit}\"}}")}}]});
        let (v, note) = verdict_cloudtrail(&by_token.to_string(), "microvm-a", "ct-1", None, &commit).unwrap().unwrap();
        assert_eq!((v.as_str(), note.as_str()), ("commitment-only", "event e3 (matched by clientToken)"));
        assert_eq!(verdict_cloudtrail(&by_token.to_string(), "microvm-a", "", None, &commit).unwrap(), None, "an empty client token matches nothing");
        // A payload whose owner says "hidden" is logged, not redacted.
        let owner = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {"runHookPayload": "{\"owner\":\"hidden@host\"}"}});
        assert_eq!(verdict_cloudtrail(&owner.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "present-other");
        for marker in ["HIDDEN_DUE_TO_SECURITY_REASONS", "redacted", "****"] {
            let m = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {"runHookPayload": marker}});
            assert_eq!(verdict_cloudtrail(&m.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "hidden", "{marker}");
        }
        // CloudTrail Lake get-query-results over LAKE_COLUMNS: one-column maps per row.
        let token = "s".repeat(64);
        let lake = |payload: &str, extra: &str| {
            serde_json::json!({"QueryStatus": "FINISHED", "QueryResultRows": [[
                {"eventID": "e4"}, {"eventName": "RunMicrovm"}, {"clientToken": "ct-9"}, {"runHookPayload": payload}, {"microvmId": "microvm-a"},
                {"requestParameters": extra}, {"responseElements": "{microvmId=microvm-a}"}]]}).to_string()
        };
        assert_eq!(verdict_cloudtrail(&lake("HIDDEN_DUE_TO_SECURITY_REASONS", "{}"), "microvm-a", "", Some(&token), &commit).unwrap().unwrap().0, "hidden");
        assert_eq!(verdict_cloudtrail(&lake("", "{}"), "microvm-a", "", None, &commit).unwrap().unwrap().0, "absent", "an empty cell is no payload");
        assert_eq!(verdict_cloudtrail(&lake("HIDDEN", &format!("{{note={token}}}")), "microvm-a", "", Some(&token), &commit).unwrap().unwrap().0, "LEAKED", "the whole row is searched");
        let short = serde_json::json!({"QueryResultRows": [[{"eventName": "RunMicrovm"}, {"microvmId": "microvm-a"}]]}).to_string();
        assert!(verdict_cloudtrail(&short, "microvm-a", "", None, &commit).unwrap_err().contains("runHookPayload") || verdict_cloudtrail(&short, "microvm-a", "", None, &commit).unwrap_err().contains("clientToken"), "a missing column is refused, not read as absent");
    }

    #[test]
    fn append_writes_one_line_per_row_and_reports_the_expectation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab").join("probes.jsonl");
        let mut row = ProbeRow::new("hooks-port", "S4", "9000", &Expectation::Exact("9000".into()));
        row.note = Some("from logs".into());
        assert!(append_row(&path, &row).unwrap());
        row.verdict = "8080".into();
        assert!(!append_row(&path, &row).unwrap(), "a verdict that misses the expectation is reported, still written");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(last_row(&path, "hooks-port").unwrap().unwrap()["verdict"], "8080");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
