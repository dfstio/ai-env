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
pub const CATALOG: [ProbeSpec; 14] = [
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
    ProbeSpec { name: "connector-pending", stage: "S5", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run connector-pending ARN (make connector-probe CONFIRM=create-probe-connector)", what: "what RunMicrovm does with an egress connector that is still PENDING (rejected:<code>, or accepted[:echo-mismatch|:internet|:terminated])" },
    ProbeSpec { name: "dns-path", stage: "S5", source: Source::Live, expect: Expect::Exact("no-dns"), recorded_by: "ai-env lab run dns-path", what: "whether a vpc VM reaches any DNS server (no-dns; platform-dns:<nameserver> for the platform's resolver; open-dns:<ip> for any other; resolves=yes|no in the note)" },
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
/// are data events: CloudTrail logs them only for a trail or a service-linked
/// channel (CloudWatch's CloudTrail ingestion, Security Lake) that selects
/// this type, and event history (`lookup-events`) never has them (AWS Lambda
/// MicroVMs docs, "Monitoring"; S4 part B, 30 Sep 2026).
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

/// Whether a trail's `get-event-selectors` document, or a channel's
/// `SourceConfig`, selects the RunMicrovm data event. Conservative: a field the
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

/// What a CloudTrail channel (`get-channel`) may do with RunMicrovm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelCover {
    /// Its selectors take RunMicrovm: the destination keeps the record.
    Logs,
    /// A service-linked channel whose selectors cannot be read: counted as keeping it.
    Maybe,
    /// Its selectors exclude RunMicrovm, or it serves only another Region.
    No,
    /// A CloudTrail Lake integration channel (external events into event data stores): not AWS API calls.
    External,
}

/// One channel as the probe sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    pub name: String,
    pub arn: String,
    pub cover: ChannelCover,
    /// The creating service for a service-linked channel (`cloudwatch`, `security-lake`, …), else `integration`.
    pub kind: String,
    /// `(Type, Location)` of each destination.
    pub destinations: Vec<(String, String)>,
}

/// Classify a `get-channel` document. Service-linked channels are named
/// `aws-service-channel/<service>/…` and deliver to `AWS_SERVICE`; CloudWatch
/// ingests CloudTrail events only through one (`aws-service-channel/cloudwatch/…`).
/// The selectors sit under `SourceConfig`, in a trail's shape. Conservative:
/// a service-linked channel without readable selectors is [`ChannelCover::Maybe`].
#[must_use]
pub fn channel_cover(doc: &serde_json::Value) -> ChannelView {
    let s = |p: &str| doc.pointer(p).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let (name, arn) = (s("/Name"), s("/ChannelArn"));
    let destinations: Vec<(String, String)> = doc
        .get("Destinations")
        .and_then(|d| d.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|d| (d.get("Type").and_then(|v| v.as_str()).unwrap_or_default().to_string(), d.get("Location").and_then(|v| v.as_str()).unwrap_or_default().to_string()))
        .collect();
    let service_linked = name.starts_with("aws-service-channel/") || destinations.iter().any(|(t, _)| t == "AWS_SERVICE");
    let kind = if let Some(rest) = name.strip_prefix("aws-service-channel/") {
        rest.split('/').next().unwrap_or(rest).to_string()
    } else if let Some((_, loc)) = destinations.iter().find(|(t, _)| t == "AWS_SERVICE") {
        loc.clone()
    } else {
        "integration".to_string()
    };
    let view = |cover| ChannelView { name: name.clone(), arn: arn.clone(), cover, kind: kind.clone(), destinations: destinations.clone() };
    if !service_linked && !destinations.is_empty() && destinations.iter().all(|(t, _)| t == "EVENT_DATA_STORE") {
        return view(ChannelCover::External);
    }
    let region = arn.split(':').nth(3).unwrap_or_default();
    if doc.pointer("/SourceConfig/ApplyToAllRegions").and_then(serde_json::Value::as_bool) == Some(false) && !region.is_empty() && region != crate::bridge::config::REGION {
        return view(ChannelCover::No);
    }
    let source = doc.get("SourceConfig");
    let readable = source.and_then(|c| c.get("AdvancedEventSelectors")).and_then(|a| a.as_array()).is_some_and(|a| !a.is_empty());
    if !readable {
        return view(ChannelCover::Maybe);
    }
    view(if source.is_some_and(selectors_log_microvm_data) { ChannelCover::Logs } else { ChannelCover::No })
}

/// `(Region, name)` of a CloudWatch Logs log group ARN
/// (`arn:aws:logs:REGION:ACCT:log-group:NAME:*`, the form `describe-trails`
/// gives as `CloudWatchLogsLogGroupArn`); `None` for anything else or a name
/// outside `[A-Za-z0-9._/#-]` (the name is printed inside a shell command).
#[must_use]
pub fn log_group_from_arn(arn: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = arn.splitn(7, ':').collect();
    if parts.len() != 7 || parts[0] != "arn" || parts[2] != "logs" || parts[3].is_empty() || parts[5] != "log-group" {
        return None;
    }
    let name = parts[6].strip_suffix(":*").unwrap_or(parts[6]);
    is_safe_log_group_name(name).then(|| (parts[3].to_string(), name.to_string()))
}

/// A log group name the probe may print inside a single-quoted shell word:
/// non-empty, `[A-Za-z0-9._/#-]` only (a subset of what CloudWatch allows).
#[must_use]
pub fn is_safe_log_group_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "._/#-".contains(c))
}

/// A redaction marker is the whole value, never a substring (a logged
/// payload's owner may say "hidden").
fn is_redaction_marker(s: &str) -> bool {
    let s = s.trim();
    s.eq_ignore_ascii_case("HIDDEN_DUE_TO_SECURITY_REASONS") || s.eq_ignore_ascii_case("REDACTED") || s.eq_ignore_ascii_case("HIDDEN") || (!s.is_empty() && s.chars().all(|c| c == '*'))
}

/// Where a record was read from (the row note names it: a CloudWatch copy may
/// have been transformed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    Trail,
    LogsRaw,
    LogsOcsf,
}

impl Provenance {
    fn label(self) -> &'static str {
        match self {
            Provenance::Trail => "CloudTrail record",
            Provenance::LogsRaw => "CloudWatch Logs, raw",
            Provenance::LogsOcsf => "CloudWatch Logs, OCSF",
        }
    }
}

/// One record: the CloudTrail shape, its raw text (searched for the session
/// token), and where it came from.
struct CtRecord {
    rec: serde_json::Value,
    raw: String,
    from: Provenance,
}

/// An OCSF `api.request.data` / `api.response.data` value as a CloudTrail
/// `requestParameters` / `responseElements`: an object, a JSON string of an
/// object, or a whole-value redaction marker; anything else is refused.
fn ocsf_data(v: Option<&serde_json::Value>, required: bool, eid: &str, what: &str) -> std::result::Result<serde_json::Value, String> {
    match v {
        None | Some(serde_json::Value::Null) if !required => Ok(serde_json::Value::Null),
        None | Some(serde_json::Value::Null) => Err(format!("CloudWatch Logs event {eid}: an OCSF record without {what}")),
        Some(o @ serde_json::Value::Object(_)) => Ok(o.clone()),
        Some(serde_json::Value::String(s)) if is_redaction_marker(s) => Ok(serde_json::Value::String(s.clone())),
        Some(serde_json::Value::String(s)) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(o @ serde_json::Value::Object(_)) => Ok(o),
            _ => Err(format!("CloudWatch Logs event {eid}: {what} is neither an object nor a JSON object string")),
        },
        Some(_) => Err(format!("CloudWatch Logs event {eid}: {what} is neither an object nor a JSON object string")),
    }
}

/// The CloudTrail records in `doc`: a trail's log file (`{"Records": [...]}`,
/// gunzipped), `aws logs filter-log-events` output (`{"events": [{"message":
/// "...", "eventId": "..."}]}` — each message a raw CloudTrail record or an
/// OCSF one mapped back: `api.operation` → eventName, `metadata.uid` →
/// eventID, `api.request.data` / `api.response.data` → requestParameters /
/// responseElements), a `lookup-events` answer (`{"Events":
/// [{"CloudTrailEvent": "..."}]}`), a JSON array of records, or one record. A
/// CloudWatch message that cannot be read is an error, never skipped: the
/// filter output holds only matches.
fn cloudtrail_records(doc: &serde_json::Value) -> std::result::Result<Vec<CtRecord>, String> {
    let own = |r: &serde_json::Value| CtRecord { rec: r.clone(), raw: r.to_string(), from: Provenance::Trail };
    if let Some(records) = doc.get("Records").and_then(|r| r.as_array()) {
        return Ok(records.iter().map(own).collect());
    }
    if let Some(events) = doc.get("events").and_then(|e| e.as_array()) {
        let mut out = Vec::new();
        for ev in events {
            let eid = ev.get("eventId").and_then(|v| v.as_str()).unwrap_or("?");
            let msg = ev.get("message").and_then(|m| m.as_str()).ok_or_else(|| format!("CloudWatch Logs event {eid} has no message"))?;
            let v: serde_json::Value = serde_json::from_str(msg).map_err(|_| format!("CloudWatch Logs event {eid}: the message is not JSON"))?;
            if v.get("eventName").is_some() {
                out.push(CtRecord { rec: v, raw: msg.to_string(), from: Provenance::LogsRaw });
                continue;
            }
            let Some(op) = v.pointer("/api/operation").and_then(|o| o.as_str()) else {
                return Err(format!("CloudWatch Logs event {eid}: neither a CloudTrail record (eventName) nor OCSF (api.operation)"));
            };
            if v.pointer("/api/request").is_none() {
                return Err(format!("CloudWatch Logs event {eid}: an OCSF record without api.request"));
            }
            let rec = serde_json::json!({
                "eventName": op,
                "eventID": v.pointer("/metadata/uid").cloned().unwrap_or(serde_json::Value::Null),
                "requestParameters": ocsf_data(v.pointer("/api/request/data"), true, eid, "api.request.data")?,
                "responseElements": ocsf_data(v.pointer("/api/response/data"), false, eid, "api.response.data")?,
            });
            out.push(CtRecord { rec, raw: msg.to_string(), from: Provenance::LogsOcsf });
        }
        return Ok(out);
    }
    if let Some(events) = doc.get("Events").and_then(|e| e.as_array()) {
        return Ok(events
            .iter()
            .filter_map(|ev| ev.get("CloudTrailEvent").and_then(|c| c.as_str()))
            .filter_map(|raw| serde_json::from_str::<serde_json::Value>(raw).ok().map(|rec| CtRecord { rec, raw: raw.to_string(), from: Provenance::Trail }))
            .collect());
    }
    if let Some(records) = doc.as_array() {
        return Ok(records.iter().map(own).collect());
    }
    if doc.get("eventName").is_some() {
        return Ok(vec![own(doc)]);
    }
    Err("not a CloudTrail document: no Records, events (CloudWatch Logs), Events or eventName".into())
}

/// cloudtrail-payload from a CloudTrail document (see [`cloudtrail_records`]):
/// every `RunMicrovm` record of this VM (matched by
/// `responseElements.microvmId` or `requestParameters.clientToken`; records
/// without an event name or of other calls on the same VM are skipped), then
/// what each kept of `runHookPayload`: `absent`, `hidden` (a redaction
/// marker), `commitment-only` (the payload with the commitment and without
/// the session token), `present-other`, or `LEAKED` when the session token
/// appears anywhere in a record. LEAKED in any record wins; records that
/// disagree otherwise are refused, as is a CloudWatch copy with masked
/// (`****`) text (fetch it with `--unmask`). `Ok(None)` when no record matched.
pub fn verdict_cloudtrail(doc_json: &str, id: &str, client_token: &str, session_token: Option<&str>, commit: &str) -> std::result::Result<Option<(String, String)>, String> {
    let doc: serde_json::Value = serde_json::from_str(doc_json).map_err(|e| format!("CloudTrail document: {e}"))?;
    let mut found: Vec<(&'static str, String)> = Vec::new();
    for r in cloudtrail_records(&doc)? {
        let inner = &r.rec;
        if inner.get("eventName").and_then(|v| v.as_str()) != Some("RunMicrovm") {
            continue;
        }
        let by_id = inner.pointer("/responseElements/microvmId").and_then(|v| v.as_str()) == Some(id);
        let by_token = !client_token.is_empty() && inner.pointer("/requestParameters/clientToken").and_then(|v| v.as_str()) == Some(client_token);
        if !(by_id || by_token) {
            continue;
        }
        let event_id = inner.get("eventID").and_then(|v| v.as_str()).unwrap_or("?");
        let label = format!("event {event_id} (matched by {}; {})", if by_id { "microvmId" } else { "clientToken" }, r.from.label());
        if session_token.is_some_and(|t| !t.is_empty() && r.raw.contains(t)) {
            return Ok(Some(("LEAKED".to_string(), format!("{label}: the session token itself is in the event"))));
        }
        if r.from != Provenance::Trail && r.raw.contains("****") {
            return Err(format!("{label} has masked text: fetch it again with --unmask"));
        }
        let verdict = match inner.get("requestParameters") {
            None | Some(serde_json::Value::Null) => "absent",
            Some(serde_json::Value::String(s)) if is_redaction_marker(s) => "hidden",
            Some(serde_json::Value::Object(_)) => match inner.pointer("/requestParameters/runHookPayload") {
                None | Some(serde_json::Value::Null) => "absent",
                Some(serde_json::Value::String(s)) if is_redaction_marker(s) => "hidden",
                Some(serde_json::Value::String(s)) if s.contains(commit) => "commitment-only",
                Some(_) => "present-other",
            },
            Some(_) => return Err(format!("{label}: requestParameters is neither an object nor a redaction marker")),
        };
        found.push((verdict, label));
    }
    let Some((first, _)) = found.first() else { return Ok(None) };
    if found.iter().any(|(v, _)| v != first) {
        let all = found.iter().map(|(v, l)| format!("{l}={v}")).collect::<Vec<_>>().join(", ");
        return Err(format!("the matching records disagree: {all}"));
    }
    Ok(Some((first.to_string(), found.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join(", "))))
}

// ---- S5: dns-path and connector-pending -----------------------------------------------------

/// One `dig` of the dns-path probe (and of `ai-env egress check`'s DNS cases):
/// which server, over which transport, dig's exit code (`None`: not asked —
/// `/etc/resolv.conf` named no nameserver), whether the reply carried an
/// address for the name, and the reply's status and recursion-available
/// flag when dig printed them (what a platform resolver that "resolves
/// nothing" does with a query: `REFUSED` without recursion is not a
/// recursive path out; `SERVFAIL` with recursion available may be one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsReply {
    pub server: String,
    /// `udp` | `tcp`.
    pub transport: &'static str,
    pub rc: Option<i32>,
    pub resolves: bool,
    pub status: Option<String>,
    pub ra: Option<bool>,
}

/// The dns-path verdict when a resolver that is not the platform's replies
/// (`open-dns:<ip>`): a failing verdict, never accepted
/// (`egress::dns_verdict_ok` refuses it).
pub const DNS_OPEN_PREFIX: &str = "open-dns:";
/// The dns-path verdict when a platform resolver resolves names (its
/// lookups reach authoritative servers: a path out):
/// `platform-dns-resolves:<ip>`, never accepted (`egress::dns_verdict_ok`
/// takes only `platform-dns:<ip>`, a resolver that answers without
/// resolving — DNS Firewall).
pub const DNS_PLATFORM_RESOLVES_PREFIX: &str = "platform-dns-resolves:";

/// A platform resolver address (a private or link-local IPv4, or
/// `fd00:ec2::/32`): exactly what `egress::dns_verdict_ok` accepts in a
/// `platform-dns:<ip>` verdict. Anything else that replies is open DNS.
#[must_use]
pub fn is_platform_resolver(ip: &str) -> bool {
    crate::bridge::egress::dns_verdict_ok(&format!("{}{ip}", crate::bridge::egress::DNS_PLATFORM_PREFIX), true)
}

/// dns-path from the digs of one VM, the worst first: `open-dns:<ip>` when
/// a server that is not a platform resolver ([`is_platform_resolver`]: a
/// public one, a local stub) replied; `platform-dns-resolves:<ip>` when a
/// platform resolver replied with an address; `platform-dns:<ip>` when one
/// replied without resolving anything (DNS Firewall); `no-dns` when no
/// server replied (dig exit 9 everywhere). The IP is the first such server.
/// The note says `resolves=yes|no` (did any reply carry an address), the
/// resolv.conf nameserver, and each server's answer (with its status and
/// whether it offered recursion). Any other dig exit code
/// is an error (nothing proven: a missing dig must never read as `no-dns`),
/// as is a probe that asked nothing.
pub fn verdict_dns_path(resolv_ns: Option<&str>, replies: &[DnsReply]) -> std::result::Result<(String, String), String> {
    if replies.iter().all(|r| r.rc.is_none()) {
        return Err("no DNS server was asked".into());
    }
    let mut servers: Vec<(String, Vec<String>)> = Vec::new();
    let mut first: Option<&str> = None;
    let mut resolving: Option<&str> = None;
    let mut open: Option<&str> = None;
    for r in replies {
        let said = match r.rc {
            None => continue,
            Some(0) => {
                if !is_platform_resolver(&r.server) {
                    open.get_or_insert(r.server.as_str());
                } else if r.resolves {
                    resolving.get_or_insert(r.server.as_str());
                } else {
                    first.get_or_insert(r.server.as_str());
                }
                let detail: Vec<String> = [r.status.clone(), r.ra.map(|a| (if a { "recursion available" } else { "no recursion" }).to_string())].into_iter().flatten().collect();
                let what = if r.resolves { "resolved" } else { "replied" };
                if detail.is_empty() { what.to_string() } else { format!("{what} ({})", detail.join(", ")) }
            }
            // A truncated UDP reply whose TCP retry failed (dig exit 9 with a status): the UDP path answered.
            Some(9) if r.status.is_some() && !is_platform_resolver(&r.server) => {
                open.get_or_insert(r.server.as_str());
                "replied (truncated; the TCP retry got nothing)".to_string()
            }
            Some(9) if r.status.is_some() => return Err(format!("{} sent a truncated reply over {} and dig's TCP retry got nothing: no verdict", r.server, r.transport)),
            Some(9) => "no reply".to_string(),
            Some(rc) => return Err(format!("dig exited {rc} asking {} over {}: no verdict (is dig in the image?)", r.server, r.transport)),
        };
        let part = format!("{} {said}", r.transport);
        match servers.iter_mut().find(|(s, _)| *s == r.server) {
            Some((_, parts)) => parts.push(part),
            None => servers.push((r.server.clone(), vec![part])),
        }
    }
    let resolves = replies.iter().any(|r| r.rc == Some(0) && r.resolves);
    let verdict = match (open, resolving, first) {
        (Some(s), _, _) => format!("{DNS_OPEN_PREFIX}{s}"),
        (None, Some(s), _) => format!("{DNS_PLATFORM_RESOLVES_PREFIX}{s}"),
        (None, None, Some(s)) => format!("{}{s}", crate::bridge::egress::DNS_PLATFORM_PREFIX),
        (None, None, None) => crate::bridge::egress::DNS_NONE.to_string(),
    };
    let asked = servers.iter().map(|(s, parts)| format!("{s} {}", parts.join(", "))).collect::<Vec<_>>().join("; ");
    Ok((verdict, format!("resolves={} resolv.conf nameserver {}; {asked}", if resolves { "yes" } else { "no" }, resolv_ns.unwrap_or("none"))))
}

/// An AWS error code: `Validation…Exception`-shaped (a capital first, then
/// letters and digits, ending in `Exception`, `Error` or `Fault`).
fn is_error_code(s: &str) -> bool {
    s.len() <= 64 && s.starts_with(|c: char| c.is_ascii_uppercase()) && s.bytes().all(|c| c.is_ascii_alphanumeric()) && ["Exception", "Error", "Fault"].iter().any(|t| s.ends_with(t))
}

/// connector-pending, refused: `rejected:<Code>` with the error code of
/// RunMicrovm's refusal — `ValidationException` or `ConflictException` for
/// those error classes, or the `Code:` an SDK error's message starts with —
/// else `rejected:unknown`; the note is the error text (at most 300
/// characters). `None` for a failure that is no verdict on the connector:
/// throttling, a quota, an access denial (the runtime policy), missing
/// credentials, an ambiguous call — the caller reports it and records
/// nothing.
#[must_use]
pub fn verdict_connector_rejected(e: &crate::bridge::errors::BridgeError) -> Option<(String, String)> {
    use crate::bridge::errors::BridgeError;
    let code = match e {
        BridgeError::Throttled(_) | BridgeError::Quota(_) | BridgeError::AccessDenied(_) | BridgeError::CredentialsUnavailable(_) | BridgeError::Ambiguous { .. } => return None,
        BridgeError::Validation(_) => Some("ValidationException".to_string()),
        BridgeError::Conflict(_) => Some("ConflictException".to_string()),
        BridgeError::Sdk { message, .. } => message.split_once(':').map(|(c, _)| c.trim()).filter(|c| is_error_code(c)).map(str::to_string),
        _ => None,
    };
    let text: String = e.to_string().chars().take(300).collect();
    Some((format!("rejected:{}", code.as_deref().unwrap_or("unknown")), format!("RunMicrovm refused the connector: {text}")))
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
    fn catalog_names_are_unique_and_cover_the_nine_s4_and_two_s5_probes() {
        let names: std::collections::BTreeSet<&str> = CATALOG.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), CATALOG.len());
        assert_eq!(CATALOG.iter().filter(|p| p.stage == "S4").count(), 9);
        assert_eq!(CATALOG.iter().filter(|p| p.stage == "S5").map(|p| p.name).collect::<Vec<_>>(), ["connector-pending", "dns-path"]);
        assert_eq!(spec("dns-path").unwrap().expect.expectation().render(), crate::bridge::egress::DNS_NONE);
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
            let inner = serde_json::json!({"eventName":"RunMicrovm","eventID":"e1","requestParameters":params,"responseElements":{"microvmId":"microvm-a"}});
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
        let nameless = serde_json::json!({"Records": [{"eventID": "e9", "requestParameters": {}, "responseElements": {"microvmId": "microvm-a"}}]}).to_string();
        assert_eq!(verdict_cloudtrail(&nameless, "microvm-a", "", None, &commit).unwrap(), None, "a record without an event name never stands in for RunMicrovm");
        // A trail's log file: the Records of other calls on the same VM (TerminateMicrovm answers with its
        // microvmId too) must not stand in for RunMicrovm, whose record shape is the AWS docs example.
        let terminate = serde_json::json!({"eventName":"TerminateMicrovm","eventID":"e0","responseElements":{"microvmId":"microvm-a"}});
        let run = serde_json::json!({"eventName":"RunMicrovm","eventID":"e2","requestParameters":{"microvmImageArn":"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent"},
            "responseElements":{"microvmId":"microvm-a","microvmState":"PENDING"},"eventCategory":"Data","managementEvent":false});
        let file = |records: Vec<&serde_json::Value>| serde_json::json!({"Records": records}).to_string();
        assert_eq!(verdict_cloudtrail(&file(vec![&terminate]), "microvm-a", "", None, &commit).unwrap(), None, "only RunMicrovm counts");
        let (v, note) = verdict_cloudtrail(&file(vec![&terminate, &run]), "microvm-a", "", Some(&token), &commit).unwrap().unwrap();
        assert_eq!((v.as_str(), note.as_str()), ("absent", "event e2 (matched by microvmId; CloudTrail record)"));
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
    fn cloudtrail_matches_by_client_token_and_exact_markers() {
        let commit = "c".repeat(64);
        // No microvmId in the record: matched by clientToken.
        let by_token = serde_json::json!({"Records": [{"eventName": "RunMicrovm", "eventID": "e3", "requestParameters": {"clientToken": "ct-1", "runHookPayload": format!("{{\"commit\":\"{commit}\"}}")}}]});
        let (v, note) = verdict_cloudtrail(&by_token.to_string(), "microvm-a", "ct-1", None, &commit).unwrap().unwrap();
        assert_eq!((v.as_str(), note.as_str()), ("commitment-only", "event e3 (matched by clientToken; CloudTrail record)"));
        assert_eq!(verdict_cloudtrail(&by_token.to_string(), "microvm-a", "", None, &commit).unwrap(), None, "an empty client token matches nothing");
        // A payload whose owner says "hidden" is logged, not redacted.
        let owner = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {"runHookPayload": "{\"owner\":\"hidden@host\"}"}});
        assert_eq!(verdict_cloudtrail(&owner.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "present-other");
        for marker in ["HIDDEN_DUE_TO_SECURITY_REASONS", "redacted", "****"] {
            let m = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {"runHookPayload": marker}});
            assert_eq!(verdict_cloudtrail(&m.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "hidden", "{marker}");
        }
        // requestParameters itself a marker (CloudTrail's form for sensitive parameters): hidden; any other scalar: refused.
        let whole = |p: serde_json::Value| serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": p}).to_string();
        assert_eq!(verdict_cloudtrail(&whole(serde_json::json!("HIDDEN_DUE_TO_SECURITY_REASONS")), "microvm-a", "", None, &commit).unwrap().unwrap().0, "hidden");
        assert!(verdict_cloudtrail(&whole(serde_json::json!("some text")), "microvm-a", "", None, &commit).is_err());
        assert!(verdict_cloudtrail(&whole(serde_json::json!(42)), "microvm-a", "", None, &commit).is_err());
    }

    #[test]
    fn cloudtrail_reads_cloudwatch_events() {
        let token = "s".repeat(64);
        let commit = "c".repeat(64);
        let payload = format!("{{\"commit\":\"{commit}\"}}");
        // `aws logs filter-log-events --output json`: one message per matching log event.
        let logs = |messages: Vec<String>| {
            let events: Vec<serde_json::Value> = messages.iter().enumerate().map(|(i, m)| serde_json::json!({"logStreamName": "s", "timestamp": 1, "message": m, "eventId": format!("ev{i}")})).collect();
            serde_json::json!({"events": events, "searchedLogStreams": []}).to_string()
        };
        let v = |messages: Vec<String>| verdict_cloudtrail(&logs(messages), "microvm-a", "", Some(&token), &commit);
        let raw = |p: &str| serde_json::json!({"eventName": "RunMicrovm", "eventID": "r1", "requestParameters": {"runHookPayload": p}, "responseElements": {"microvmId": "microvm-a"}}).to_string();
        let ocsf = |op: &str, request: serde_json::Value| serde_json::json!({"class_uid": 6003, "metadata": {"uid": "o1"}, "api": {"operation": op, "request": request, "response": {"data": {"microvmId": "microvm-a"}}}}).to_string();
        let (verdict, note) = v(vec![raw("HIDDEN_DUE_TO_SECURITY_REASONS")]).unwrap().unwrap();
        assert_eq!((verdict.as_str(), note.as_str()), ("hidden", "event r1 (matched by microvmId; CloudWatch Logs, raw)"));
        assert_eq!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": {"microvmImageArn": "x"}}))]).unwrap().unwrap().0, "absent", "OCSF, object data");
        assert_eq!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": {"runHookPayload": "other"}}))]).unwrap().unwrap().0, "present-other");
        let (verdict, note) = v(vec![ocsf("RunMicrovm", serde_json::json!({"data": serde_json::json!({"runHookPayload": payload}).to_string()}))]).unwrap().unwrap();
        assert_eq!((verdict.as_str(), note.as_str()), ("commitment-only", "event o1 (matched by microvmId; CloudWatch Logs, OCSF)"), "OCSF data as a JSON string");
        assert_eq!(v(vec![ocsf("TerminateMicrovm", serde_json::json!({"data": {}}))]).unwrap(), None, "other operations are skipped");
        let leaked = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {}, "userAgent": token}).to_string();
        assert_eq!(v(vec![leaked.clone()]).unwrap().unwrap().0, "LEAKED", "anywhere in the message");
        assert_eq!(v(vec![raw(&payload), leaked]).unwrap().unwrap().0, "LEAKED", "a later LEAKED record wins");
        assert!(v(vec![raw(&payload), raw("other")]).unwrap_err().contains("disagree"), "records that disagree are refused");
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": "{not json"}))]).unwrap_err().contains("api.request.data"));
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": 7}))]).is_err());
        assert!(v(vec![serde_json::json!({"api": {"operation": "RunMicrovm"}}).to_string()]).unwrap_err().contains("without api.request"));
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"uid": "q"}))]).unwrap_err().contains("without api.request.data"));
        assert!(v(vec!["plain text line".to_string()]).unwrap_err().contains("ev0: the message is not JSON"), "never skipped: the filter output holds only matches");
        assert!(v(vec![serde_json::json!({"hello": 1}).to_string()]).unwrap_err().contains("neither a CloudTrail record"));
        assert!(v(vec![raw("{\"commit\":\"********\"}")]).unwrap_err().contains("--unmask"), "masked text is refused, not called hidden");
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": {"runHookPayload": "{\"owner\":\"****\"}"}}))]).unwrap_err().contains("--unmask"), "an OCSF record with a 4-star mask too");
        // The token anywhere in the OCSF message, outside what is mapped back: LEAKED.
        let actor = serde_json::json!({"metadata": {"uid": "o2"}, "actor": {"session": token}, "api": {"operation": "RunMicrovm", "request": {"data": {}}, "response": {"data": {"microvmId": "microvm-a"}}}}).to_string();
        assert_eq!(v(vec![actor]).unwrap().unwrap().0, "LEAKED");
        // Optional OCSF shapes: request data that is a redaction marker, and no response (matched by clientToken).
        assert_eq!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": "HIDDEN_DUE_TO_SECURITY_REASONS"}))]).unwrap().unwrap().0, "hidden");
        let no_response = serde_json::json!({"metadata": {"uid": "o3"}, "api": {"operation": "RunMicrovm", "request": {"data": {"clientToken": "ct-5"}}}}).to_string();
        let (verdict, note) = verdict_cloudtrail(&logs(vec![no_response]), "microvm-a", "ct-5", Some(&token), &commit).unwrap().unwrap();
        assert_eq!((verdict.as_str(), note.as_str()), ("absent", "event o3 (matched by clientToken; CloudWatch Logs, OCSF)"));
        assert_eq!(v(vec![]).unwrap(), None);
    }

    #[test]
    fn channel_cover_cases() {
        let arn = |region: &str, name: &str| format!("arn:aws:cloudtrail:{region}:123456789012:channel/{name}");
        let data_sel = serde_json::json!([{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}]}]);
        // The live Resource Explorer channel (shape seen 30 Sep 2026): management events only.
        let rex = serde_json::json!({"ChannelArn": arn("eu-central-1", "aws-service-channel/resource-explorer-2"), "Name": "aws-service-channel/resource-explorer-2/AwsResourceExplorerDefault", "Source": "CloudTrail",
            "SourceConfig": {"ApplyToAllRegions": true, "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]},
            "Destinations": [{"Type": "AWS_SERVICE", "Location": "resource-explorer-2"}]});
        let c = channel_cover(&rex);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::No, "resource-explorer-2"));
        let cw = serde_json::json!({"ChannelArn": arn("eu-central-1", "cw-1"), "Name": "aws-service-channel/cloudwatch/rule-1", "SourceConfig": {"ApplyToAllRegions": true, "AdvancedEventSelectors": data_sel},
            "Destinations": [{"Type": "AWS_SERVICE", "Location": "cloudwatch"}]});
        let c = channel_cover(&cw);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::Logs, "cloudwatch"));
        assert!(!selectors_log_microvm_data(&cw), "the selectors sit under SourceConfig: the whole document never matches");
        let mut no_source = cw.clone();
        no_source.as_object_mut().unwrap().remove("SourceConfig");
        assert_eq!(channel_cover(&no_source).cover, ChannelCover::Maybe, "unreadable selectors: may log");
        let mut empty = cw.clone();
        empty["SourceConfig"]["AdvancedEventSelectors"] = serde_json::json!([]);
        assert_eq!(channel_cover(&empty).cover, ChannelCover::Maybe);
        let lake = serde_json::json!({"ChannelArn": arn("eu-central-1", "int-1"), "Name": "partner-integration", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "arn:aws:cloudtrail:eu-central-1:123456789012:eventdatastore/eds-1"}]});
        let c = channel_cover(&lake);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::External, "integration"));
        let mut elsewhere = cw.clone();
        elsewhere["ChannelArn"] = serde_json::json!(arn("us-east-1", "cw-2"));
        elsewhere["SourceConfig"]["ApplyToAllRegions"] = serde_json::json!(false);
        assert_eq!(channel_cover(&elsewhere).cover, ChannelCover::No, "a single-Region channel of another Region");
        elsewhere["SourceConfig"]["ApplyToAllRegions"] = serde_json::json!(true);
        assert_eq!(channel_cover(&elsewhere).cover, ChannelCover::Logs, "an all-Region channel homed elsewhere covers this Region");
        let mut here_only = cw.clone();
        here_only["SourceConfig"]["ApplyToAllRegions"] = serde_json::json!(false);
        assert_eq!(channel_cover(&here_only).cover, ChannelCover::Logs, "a single-Region channel of eu-central-1 covers it");
        // External only for a non-service channel whose destinations are all event data stores.
        let nowhere = serde_json::json!({"ChannelArn": arn("eu-central-1", "n"), "Name": "partner", "Destinations": []});
        assert_eq!(channel_cover(&nowhere).cover, ChannelCover::Maybe, "no destinations: unknown, not External");
        let service_to_store = serde_json::json!({"ChannelArn": arn("eu-central-1", "s"), "Name": "aws-service-channel/cloudwatch/y", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "arn:aws:cloudtrail:eu-central-1:123456789012:eventdatastore/eds-2"}]});
        assert_ne!(channel_cover(&service_to_store).cover, ChannelCover::External, "a service-linked name is never an integration channel");
        let unnamed_service = serde_json::json!({"ChannelArn": arn("eu-central-1", "x"), "Name": "x", "Destinations": [{"Type": "AWS_SERVICE", "Location": "security-lake"}]});
        let c = channel_cover(&unnamed_service);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::Maybe, "security-lake"));
    }

    #[test]
    fn log_group_arn_cases() {
        let g = |a: &str| log_group_from_arn(a);
        assert_eq!(g("arn:aws:logs:eu-central-1:123456789012:log-group:aws-cloudtrail-logs-1:*"), Some(("eu-central-1".into(), "aws-cloudtrail-logs-1".into())));
        assert_eq!(g("arn:aws:logs:eu-central-1:123456789012:log-group:aws/cloudtrail/data"), Some(("eu-central-1".into(), "aws/cloudtrail/data".into())));
        assert_eq!(g("arn:aws:logs:us-east-1:123456789012:log-group:/aws/ct:*"), Some(("us-east-1".into(), "/aws/ct".into())));
        assert_eq!(g("arn:aws:logs:eu-central-1:123456789012:log-group:bad name'x:*"), None, "a name this probe will not print");
        assert_eq!(g("arn:aws:s3:::bucket"), None);
        assert_eq!(g("garbage"), None);
        assert!(is_safe_log_group_name("aws/cloudtrail/data-events") && !is_safe_log_group_name("") && !is_safe_log_group_name("a'b"));
    }

    fn reply(server: &str, transport: &'static str, rc: Option<i32>, resolves: bool) -> DnsReply {
        DnsReply { server: server.into(), transport, rc, resolves, status: None, ra: None }
    }

    #[test]
    fn dns_path_verdicts() {
        let closed = [
            reply("10.42.0.2", "udp", Some(9), false),
            reply("10.42.0.2", "tcp", Some(9), false),
            reply("169.254.169.253", "udp", Some(9), false),
            reply("169.254.169.253", "tcp", Some(9), false),
        ];
        let (v, note) = verdict_dns_path(Some("10.42.0.2"), &closed).unwrap();
        assert_eq!(v, crate::bridge::egress::DNS_NONE);
        assert_eq!(note, "resolves=no resolv.conf nameserver 10.42.0.2; 10.42.0.2 udp no reply, tcp no reply; 169.254.169.253 udp no reply, tcp no reply");
        assert_eq!(spec("dns-path").unwrap().expect.expectation().render(), v, "the expectation");
        // DNS Firewall (dnsMode firewall): the platform resolver replies and resolves nothing.
        let firewall = [reply("", "udp", None, false), reply("169.254.169.253", "udp", Some(0), false), reply("10.42.1.2", "udp", Some(9), false)];
        let (v, note) = verdict_dns_path(None, &firewall).unwrap();
        assert_eq!(v, "platform-dns:169.254.169.253");
        assert!(note.starts_with("resolves=no resolv.conf nameserver none;") && note.contains("169.254.169.253 udp replied"), "{note}");
        // A platform resolver that resolves names (its lookups leave): its own verdict, never accepted — and it wins
        // over one that only replies; resolves=yes when any reply carried an address.
        let open = [reply("10.42.0.2", "udp", Some(9), false), reply("169.254.169.253", "udp", Some(0), false), reply("10.42.1.2", "tcp", Some(0), true)];
        let (v, note) = verdict_dns_path(Some("10.42.0.2"), &open).unwrap();
        assert_eq!(v, "platform-dns-resolves:10.42.1.2");
        assert!(note.starts_with("resolves=yes") && note.contains("10.42.1.2 tcp resolved") && note.contains("169.254.169.253 udp replied"), "{note}");
        assert!(!crate::bridge::egress::dns_verdict_ok(&v, true) && !crate::bridge::egress::dns_verdict_ok(&v, false), "never accepted");
        assert!(!expectation_holds("no-dns", &v));
        // A platform resolver that answers without resolving (DNS Firewall): platform-dns, accepted only with the operator's acceptance.
        let (v, _) = verdict_dns_path(None, &[reply("169.254.169.253", "udp", Some(0), false), reply("10.42.1.2", "udp", Some(9), false)]).unwrap();
        assert_eq!(v, "platform-dns:169.254.169.253");
        assert!(crate::bridge::egress::dns_verdict_ok(&v, true) && !crate::bridge::egress::dns_verdict_ok(&v, false));
        // A resolver that is not the platform's (public, a local stub) replying is open DNS, whatever else replied.
        for (ns, server) in [("1.1.1.1", "1.1.1.1"), ("10.42.0.2", "9.9.9.9"), ("127.0.0.53", "127.0.0.53")] {
            let open = [reply("169.254.169.253", "udp", Some(0), false), reply(server, "udp", Some(0), false), reply("10.42.1.2", "tcp", Some(9), false)];
            let (v, note) = verdict_dns_path(Some(ns), &open).unwrap();
            assert_eq!(v, format!("open-dns:{server}"), "{note}");
            assert!(!crate::bridge::egress::dns_verdict_ok(&v, true), "never accepted");
            assert!(expectation_holds(&spec("dns-path").unwrap().expect.expectation().render(), "no-dns") && !expectation_holds("no-dns", &v));
        }
        assert_eq!(verdict_dns_path(None, &[reply("fd00:ec2::253", "udp", Some(0), false)]).unwrap().0, "platform-dns:fd00:ec2::253");
        assert_eq!(verdict_dns_path(None, &[reply("fd00:ec2::253", "udp", Some(0), true)]).unwrap().0, "platform-dns-resolves:fd00:ec2::253");
        assert_eq!(verdict_dns_path(None, &[reply("10.42.1.2", "udp", Some(0), true), reply("9.9.9.9", "tcp", Some(0), false)]).unwrap().0, "open-dns:9.9.9.9", "open DNS is worse");
        assert_eq!(verdict_dns_path(None, &[reply("2606:4700:4700::1111", "tcp", Some(0), false)]).unwrap().0, "open-dns:2606:4700:4700::1111");
        for platform in ["10.42.0.2", "10.42.1.2", "169.254.169.253", "fd00:ec2::253", "172.16.0.2", "192.168.0.2"] {
            assert!(is_platform_resolver(platform), "{platform}");
        }
        for public in ["1.1.1.1", "9.9.9.9", "208.67.222.222", "127.0.0.53", "2606:4700:4700::1111", "::1", "100.64.0.2", "resolver", ""] {
            assert!(!is_platform_resolver(public), "{public}");
        }
        // Nothing proven: a dig that did not run (127: not in the image) or failed, or nothing asked.
        assert!(verdict_dns_path(None, &[reply("169.254.169.253", "udp", Some(127), false)]).unwrap_err().contains("exited 127"));
        assert!(verdict_dns_path(None, &[reply("169.254.169.253", "udp", Some(10), false)]).is_err());
        assert!(verdict_dns_path(None, &[reply("", "udp", None, false)]).is_err());
        // A truncated UDP reply whose TCP retry got nothing (dig exit 9 with a status): never "no reply".
        let truncated = |server: &str| DnsReply { status: Some("TRUNCATED".into()), ..reply(server, "udp", Some(9), false) };
        let (v, note) = verdict_dns_path(None, &[truncated("1.1.1.1")]).unwrap();
        assert!(v == "open-dns:1.1.1.1" && note.contains("1.1.1.1 udp replied (truncated; the TCP retry got nothing)"), "{v}: {note}");
        assert!(verdict_dns_path(None, &[truncated("fd00:ec2::253")]).unwrap_err().contains("truncated reply over udp"));
        // The status and the recursion flag reach the note.
        let refused = DnsReply { status: Some("REFUSED".into()), ra: Some(false), ..reply("fd00:ec2::253", "tcp", Some(0), false) };
        assert!(verdict_dns_path(None, &[refused]).unwrap().1.ends_with("fd00:ec2::253 tcp replied (REFUSED, no recursion)"));
        assert!(verdict_dns_path(None, &[]).is_err());
    }

    #[test]
    fn connector_pending_rejections_name_the_code() {
        use crate::bridge::errors::BridgeError;
        let msg = "Network connector arn:aws:lambda:eu-central-1:123456789012:network-connector:probe is not ACTIVE";
        let (v, note) = verdict_connector_rejected(&BridgeError::Validation(msg.into())).unwrap();
        assert_eq!(v, "rejected:ValidationException");
        assert!(note.starts_with("RunMicrovm refused the connector: aws validation: Network connector") && note.contains("is not ACTIVE"), "{note}");
        for (e, code) in [
            (BridgeError::Conflict("x".into()), "ConflictException"),
            (BridgeError::Sdk { op: "run_microvm", message: "ResourceNotFoundException: Network connector x not found".into() }, "ResourceNotFoundException"),
            (BridgeError::Sdk { op: "run_microvm", message: "InvalidParameterValueError: x".into() }, "InvalidParameterValueError"),
        ] {
            assert_eq!(verdict_connector_rejected(&e).unwrap().0, format!("rejected:{code}"), "{e}");
        }
        // No code in the text: unknown, the message kept in the note.
        for message in ["the connector is pending", "timeout: no answer", "lowercaseException: x", ""] {
            let (v, note) = verdict_connector_rejected(&BridgeError::Sdk { op: "run_microvm", message: message.into() }).unwrap();
            assert_eq!(v, "rejected:unknown", "{message:?}");
            assert!(note.contains(message), "{note}");
        }
        assert_eq!(verdict_connector_rejected(&BridgeError::Endpoint("x".into())).unwrap().0, "rejected:unknown");
        let long = verdict_connector_rejected(&BridgeError::Validation("y".repeat(1000))).unwrap().1;
        assert!(long.chars().count() <= 300 + "RunMicrovm refused the connector: ".len(), "{}", long.len());
        // Throttling, a quota, the runtime policy, credentials, an ambiguous call: no verdict on the connector.
        for e in [
            BridgeError::Throttled("Rate exceeded".into()),
            BridgeError::Quota("Max allocated ARM_64 MicroVM memory".into()),
            BridgeError::AccessDenied("run_microvm: not authorized to perform lambda:PassNetworkConnector".into()),
            BridgeError::CredentialsUnavailable("expired".into()),
            BridgeError::Ambiguous { op: "run_microvm", message: "timeout".into() },
        ] {
            assert!(verdict_connector_rejected(&e).is_none(), "{e}");
        }
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
