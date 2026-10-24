//! `ai-env gates` — the G1–G8 pre-code gates of the MicroVM plan. G1, G2, G7
//! are re-measured on every run; G3 re-inspects the last `make vm-build`
//! output (it never rebuilds it); G6 checks the plugin and leaves the preview
//! to a hand record. Manual rows (G4 without a token, G5, G6, G8) and skipped
//! rows but G7's keep whatever the existing `plans/gates.md` records (a
//! skipped row only a record of its own gate, the same id and name), unless
//! that text is the tool's own placeholder; a skipped G7 (no state or no
//! identity to simulate as) always shows why. GO requires G1–G5 ✓ on a full
//! run; `--only` never evaluates go/no-go and never writes the file.
//!
//! S8 operators: G2 and G7 run as the operator identity (`bridge::identity`:
//! `ai-env as …`, else `credentials/ops.env`, one Touch ID), resolved once
//! before G1 when either runs. G7 is "IAM of the operator identities": eight
//! `simulate-principal-policy` calls of the stack's users from
//! `state/infra.toml`, never of the caller, and no sts call of its own, so
//! its verdict does not depend on who runs it.
use crate::bridge::awscli::{arn_account, operator_capture};
use crate::bridge::config::REGION;
use crate::bridge::doctor::{capture, run_capture};
use crate::bridge::egress::PARAMETER_PREFIX;
use crate::bridge::infra::{read_infra_state, InfraState};
use crate::commands::json_string;
use crate::errors::{CliError, Result};
use crate::outln;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    Fail,
    Manual,
    Skipped,
}

impl GateStatus {
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            GateStatus::Pass => "✓",
            GateStatus::Fail => "✗",
            GateStatus::Manual => "?",
            GateStatus::Skipped => "–",
        }
    }

    #[must_use]
    pub fn from_glyph(g: &str) -> Option<GateStatus> {
        match g.trim() {
            "✓" => Some(GateStatus::Pass),
            "✗" => Some(GateStatus::Fail),
            "?" => Some(GateStatus::Manual),
            "–" | "-" => Some(GateStatus::Skipped),
            _ => None,
        }
    }

    #[must_use]
    pub fn json_name(self) -> &'static str {
        match self {
            GateStatus::Pass => "pass",
            GateStatus::Fail => "fail",
            GateStatus::Manual => "manual",
            GateStatus::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateResult {
    pub id: &'static str,
    pub name: &'static str,
    pub command: String,
    pub expected: String,
    pub observed: String,
    pub status: GateStatus,
    pub date: String,
}

pub const KNOWN: [&str; 8] = ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"];
const BLOCKING: [&str; 5] = ["G1", "G2", "G3", "G4", "G5"];

fn today() -> String {
    crate::wire::time::rfc3339_utc(crate::wire::time::unix_now())[..10].to_string()
}

fn gate(id: &'static str, name: &'static str, command: &str, expected: &str, observed: String, status: GateStatus) -> GateResult {
    GateResult { id, name, command: command.to_string(), expected: expected.to_string(), observed, status, date: today() }
}

fn llvm_tool(name: &str) -> String {
    let brew = format!("/opt/homebrew/opt/llvm/bin/{name}");
    if Path::new(&brew).is_file() {
        brew
    } else {
        name.to_string()
    }
}

// ---- pure helpers (unit-tested) ------------------------------------------------------

/// Highest `GLIBC_2.<minor>` version referenced in `llvm-objdump -T` output.
#[must_use]
pub fn max_glibc_minor(objdump_out: &str) -> Option<u32> {
    objdump_out
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter_map(|tok| tok.strip_prefix("GLIBC_2."))
        .filter_map(|rest| rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse::<u32>().ok())
        .max()
}

/// Number of `getentropy` symbols in `llvm-nm -D` output. nm prints versioned
/// names (`getentropy@GLIBC_2.25`), so the name is compared before the `@`.
#[must_use]
pub fn count_getentropy(nm_out: &str) -> usize {
    nm_out
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter(|sym| sym.split('@').next() == Some("getentropy"))
        .count()
}

/// `pulumi plugin ls --json` lists `{name, kind, version}` objects.
#[must_use]
pub fn plugin_listed(json: &str, name: &str, kind: &str, version: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.as_array().cloned()).is_some_and(|arr| {
        arr.iter().any(|p| {
            p.get("name").and_then(|x| x.as_str()) == Some(name)
                && p.get("kind").and_then(|x| x.as_str()) == Some(kind)
                && p.get("version").and_then(|x| x.as_str()).is_some_and(|v| v.trim_start_matches('v') == version)
        })
    })
}

/// Ids in `only` that are not gates (case-insensitive), for the usage error.
#[must_use]
pub fn unknown_ids(only: &[String]) -> Vec<String> {
    only.iter().filter(|o| !KNOWN.iter().any(|k| k.eq_ignore_ascii_case(o))).cloned().collect()
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn any_newer(dir: &Path, than: SystemTime) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if any_newer(&p, than) {
                return true;
            }
        } else if mtime(&p).is_some_and(|t| t > than) {
            return true;
        }
    }
    false
}

/// Build inputs newer than the cross-built binary (the binary is stale).
#[must_use]
pub fn stale_inputs(repo_root: &Path, bin_mtime: SystemTime) -> Vec<String> {
    let mut stale = Vec::new();
    for rel in ["Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "crates/ai-env-cli/Cargo.toml"] {
        if mtime(&repo_root.join(rel)).is_some_and(|t| t > bin_mtime) {
            stale.push(rel.to_string());
        }
    }
    if any_newer(&repo_root.join("crates").join("ai-env-cli").join("src"), bin_mtime) {
        stale.push("crates/ai-env-cli/src".to_string());
    }
    stale
}

// ---- gate runners -----------------------------------------------------------------

fn g1(repo_root: &Path) -> GateResult {
    let t = Duration::from_secs(20);
    let mut obs = Vec::new();
    let mut ok = true;
    match run_capture("rustup", &["run", "1.98.1", "rustc", "--version"], t) {
        Ok(v) if v.contains("1.98.1") => obs.push(v),
        Ok(v) => {
            ok = false;
            obs.push(format!("unexpected rustc: {v}"));
        }
        Err(e) => {
            ok = false;
            obs.push(e);
        }
    }
    match run_capture("rustup", &["+1.98.1", "target", "list", "--installed"], t) {
        Ok(list) if list.lines().any(|l| l.trim() == "aarch64-unknown-linux-gnu") => obs.push("aarch64-unknown-linux-gnu installed".into()),
        Ok(_) => {
            ok = false;
            obs.push("aarch64-unknown-linux-gnu NOT installed (rustup target add aarch64-unknown-linux-gnu --toolchain 1.98.1)".into());
        }
        Err(e) => {
            ok = false;
            obs.push(e);
        }
    }
    // cargo's own exit status decides — never a shell pipeline's.
    let manifest = repo_root.join("Cargo.toml");
    match run_capture("cargo", &["+1.98.1", "fetch", "--locked", "--quiet", "--manifest-path", &manifest.to_string_lossy()], Duration::from_secs(600)) {
        Ok(_) => obs.push("cargo fetch --locked ok".into()),
        Err(e) => {
            ok = false;
            obs.push(format!("cargo fetch: {e}"));
        }
    }
    gate(
        "G1",
        "toolchain + SDK fetch",
        "rustup run 1.98.1 rustc --version; rustup +1.98.1 target list --installed; cargo +1.98.1 fetch --locked --quiet --manifest-path <repo>/Cargo.toml",
        "rustc 1.98.1; aarch64-unknown-linux-gnu; fetch ok",
        obs.join("; "),
        if ok { GateStatus::Pass } else { GateStatus::Fail },
    )
}

/// G2 as the operator identity (`operator`: its resolution, `Err` the
/// labelled refusal); the `aws --version` probe stays plain. It passes when
/// eu-central-1 lists `al2023-1`. eu-west-3's answer is recorded, never
/// judged: its 403 was S0's sign that the service ran in eu-central-1 alone
/// (the profile's default region had none), not an IAM pin. AWS has since
/// opened it there (part B, 22 Oct 2026), and ai-env pins its region in code
/// (T3.5's negative, `make preview-scratch NEGATIVE=region`).
fn g2(operator: Option<&std::result::Result<(), String>>) -> GateResult {
    let t = Duration::from_secs(30);
    if run_capture("aws", &["--version"], Duration::from_secs(5)).is_err() {
        return gate("G2", "region + API", "aws lambda-microvms list-managed-microvm-images", "al2023-1 listed (eu-west-3 recorded)", "aws cli not found".into(), GateStatus::Skipped);
    }
    if let Some(Err(e)) = operator {
        return gate("G2", "region + API", "aws lambda-microvms list-managed-microvm-images --region eu-central-1 | --region eu-west-3", "al2023-1 listed (eu-west-3 recorded)", e.clone(), GateStatus::Fail);
    }
    let central = operator_capture(&["lambda-microvms", "list-managed-microvm-images", "--region", "eu-central-1", "--output", "json"], t);
    let west = operator_capture(&["lambda-microvms", "list-managed-microvm-images", "--region", "eu-west-3", "--output", "json"], t);
    let central_ok = central.as_ref().is_ok_and(|j| j.contains("al2023-1"));
    let obs = format!(
        "eu-central-1: {}; eu-west-3: {}",
        match &central {
            Ok(_) if central_ok => "al2023-1 listed".to_string(),
            Ok(j) => format!("unexpected: {}", j.chars().take(80).collect::<String>()),
            Err(e) => e.clone(),
        },
        match &west {
            Err(e) => e.clone(),
            Ok(_) => "answers too (the service runs there now; ai-env stays pinned to eu-central-1)".to_string(),
        }
    );
    gate(
        "G2",
        "region + API",
        "aws lambda-microvms list-managed-microvm-images --region eu-central-1 | --region eu-west-3",
        "al2023-1 listed (eu-west-3 recorded)",
        obs,
        if central_ok { GateStatus::Pass } else { GateStatus::Fail },
    )
}

/// The image's base container: the `FROM` operand of `image/Dockerfile`
/// (digest-pinned since S3; the Makefile's `BASE_IMAGE` reads the same line).
#[must_use]
pub fn from_line(dockerfile: &str) -> Option<String> {
    dockerfile.lines().find_map(|l| l.trim_start().strip_prefix("FROM ")).map(|s| s.split_whitespace().next().unwrap_or("").to_string()).filter(|s| !s.is_empty())
}

/// The fallback when `image/Dockerfile` is unreadable.
const BASE_TAG: &str = "public.ecr.aws/lambda/microvms:al2023-minimal";

fn g3(repo_root: &Path) -> GateResult {
    let bin = repo_root.join("image").join("ai-env");
    let cmd = "inspect image/ai-env from the last make vm-build (not rebuilt here): file; llvm-objdump -T; llvm-nm -D; docker run … al2023-minimal";
    let expected = "ELF aarch64 runs on AL2023 arm64; max GLIBC ≤ 2.34; getentropy count 0";
    if !bin.is_file() {
        return gate("G3", "cross build on AL2023 arm64", cmd, expected, "image/ai-env missing — run: make vm-build".into(), GateStatus::Skipped);
    }
    let b = bin.to_string_lossy().into_owned();
    let mut obs = Vec::new();
    let mut ok = true;
    let file = run_capture("file", &[&b], Duration::from_secs(10)).unwrap_or_default();
    if file.contains("aarch64") && file.contains("ELF") {
        obs.push("ELF aarch64".into());
    } else {
        ok = false;
        obs.push(format!("not an aarch64 ELF: {file}"));
    }
    match run_capture(&llvm_tool("llvm-objdump"), &["-T", &b], Duration::from_secs(20)) {
        Ok(out) => match max_glibc_minor(&out) {
            Some(minor) if minor <= 34 => obs.push(format!("max GLIBC_2.{minor}")),
            Some(minor) => {
                ok = false;
                obs.push(format!("glibc ceiling exceeded: GLIBC_2.{minor} > 2.34"));
            }
            None => {
                ok = false;
                obs.push("no GLIBC_2.x symbol versions found (static? wrong file?)".into());
            }
        },
        Err(e) => {
            ok = false;
            obs.push(format!("llvm-objdump: {e}"));
        }
    }
    match run_capture(&llvm_tool("llvm-nm"), &["-D", &b], Duration::from_secs(20)) {
        Ok(out) => match count_getentropy(&out) {
            0 => obs.push("getentropy refs 0".into()),
            n => {
                ok = false;
                obs.push(format!("getentropy refs {n}"));
            }
        },
        Err(e) => {
            ok = false;
            obs.push(format!("llvm-nm: {e}"));
        }
    }
    let dir = bin.parent().unwrap_or(repo_root).to_string_lossy().into_owned();
    let base = std::fs::read_to_string(repo_root.join("image").join("Dockerfile")).ok().and_then(|d| from_line(&d)).unwrap_or_else(|| BASE_TAG.to_string());
    let docker = run_capture(
        "docker",
        &["run", "--rm", "--platform", "linux/arm64", "--entrypoint", "/b/ai-env", "-v", &format!("{dir}:/b:ro"), &base, "--version"],
        Duration::from_secs(120),
    );
    match docker {
        Ok(v) if v.contains("ai-env") => obs.push(format!("docker: {v}")),
        Ok(v) => {
            ok = false;
            obs.push(format!("docker unexpected: {v}"));
        }
        Err(e) => {
            ok = false;
            obs.push(format!("docker: {e}"));
        }
    }
    if let Some(bin_mtime) = mtime(&bin) {
        let stale = stale_inputs(repo_root, bin_mtime);
        if !stale.is_empty() {
            obs.push(format!("WARNING image/ai-env older than {} — rerun: make vm-build", stale.join(", ")));
        }
    }
    gate("G3", "cross build on AL2023 arm64", cmd, expected, obs.join("; "), if ok { GateStatus::Pass } else { GateStatus::Fail })
}

fn g4() -> GateResult {
    let cmd = "bundled claude -p --output-format stream-json --input-format stream-json --verbose --session-mirror (one message on stdin)";
    let expected = "≥1 transcript_mirror frame; filePath under the temp projects dir; one result";
    let token = std::env::var("CLAUDE_CODE_OAUTH_TOKEN").ok().filter(|t| !t.is_empty());
    let enabled = std::env::var("AI_ENV_CLAUDE_TESTS").ok().as_deref() == Some("1");
    let (Some(token), true) = (token, enabled) else {
        return gate("G4", "--session-mirror on the bundled CLI", cmd, expected, "manual: set AI_ENV_CLAUDE_TESTS=1 and CLAUDE_CODE_OAUTH_TOKEN to automate".into(), GateStatus::Manual);
    };
    let ext_dir = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(".cursor").join("extensions");
    let dirs = crate::bridge::doctor::installed_extension_names(&ext_dir);
    let Some((ver, dir)) = crate::bridge::doctor::pick_bundle(&dirs) else {
        return gate("G4", "--session-mirror on the bundled CLI", cmd, expected, "no Cursor Claude extension bundle found".into(), GateStatus::Fail);
    };
    let bin = ext_dir.join(dir).join("resources").join("native-binary").join("claude");
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return gate("G4", "--session-mirror on the bundled CLI", cmd, expected, format!("tempdir: {e}"), GateStatus::Fail),
    };
    let msg = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"Reply with the single word pong.\"}]}}\n";
    // The token travels in the child's environment and the message on its
    // stdin — neither ever appears on a command line.
    let mut child = std::process::Command::new(&bin);
    child
        .args(["-p", "--output-format", "stream-json", "--input-format", "stream-json", "--verbose", "--session-mirror"])
        .env("CLAUDE_CONFIG_DIR", tmp.path())
        .env("CLAUDE_CODE_OAUTH_TOKEN", &token);
    let observed = match capture(child, Some(msg.as_bytes()), Duration::from_secs(120)) {
        Ok(c) => {
            let mirrors = c.stdout.lines().filter(|l| l.contains("\"type\":\"transcript_mirror\"")).count();
            let results = c.stdout.lines().filter(|l| l.contains("\"type\":\"result\"")).count();
            let under_tmp = c.stdout.contains(&format!("{}/projects/", tmp.path().to_string_lossy()));
            let status = if c.success && mirrors >= 1 && results == 1 && under_tmp { GateStatus::Pass } else { GateStatus::Fail };
            let mut text = format!("claude {ver}: {mirrors} transcript_mirror, {results} result, filePath under tmp: {under_tmp}");
            if !c.success {
                text.push_str(&format!("; exit {:?}: {}", c.code, c.stderr.trim().lines().next().unwrap_or("")));
            }
            return gate("G4", "--session-mirror on the bundled CLI", cmd, expected, text, status);
        }
        Err(e) => e,
    };
    gate("G4", "--session-mirror on the bundled CLI", cmd, expected, observed, GateStatus::Fail)
}

fn g5() -> GateResult {
    gate(
        "G5",
        "setup-token viability",
        "claude setup-token; stream-json turn with an empty CLAUDE_CONFIG_DIR; remote-control refused",
        "result frame; remote-control refusal recorded verbatim",
        "manual: interactive login".into(),
        GateStatus::Manual,
    )
}

fn g6() -> GateResult {
    let cmd = "pulumi plugin install resource aws-native 1.79.0; pulumi preview (aws-native:region=eu-central-1) — the preview is recorded by hand";
    let expected = "plugin listed; preview passes";
    match run_capture("pulumi", &["plugin", "ls", "--json"], Duration::from_secs(20)) {
        Err(e) if e.contains("No such file") || e.contains("not found") => gate("G6", "aws-native plugin", cmd, expected, "pulumi not found".into(), GateStatus::Skipped),
        Err(e) => gate("G6", "aws-native plugin", cmd, expected, e, GateStatus::Fail),
        Ok(json) => {
            if plugin_listed(&json, "aws-native", "resource", "1.79.0") {
                // A listed plugin is not a passing preview: the gate stays a
                // hand record until someone writes the preview result in.
                gate("G6", "aws-native plugin", cmd, expected, "aws-native 1.79.0 installed; preview recorded by hand".into(), GateStatus::Manual)
            } else {
                gate("G6", "aws-native plugin", cmd, expected, "aws-native 1.79.0 not installed (pulumi plugin install resource aws-native 1.79.0)".into(), GateStatus::Fail)
            }
        }
    }
}

// ---- G7: IAM of the operator identities (S8 operators §8.1) --------------------------------

const G7_NAME: &str = "IAM of the operator identities";
const G7_COMMAND: &str = "aws iam simulate-principal-policy (8 calls): user/ai-env-deployer's 4 pairs, user/ai-env-ops' 20 deploy actions";
const G7_EXPECTED: &str = "the deployer's 4 pairs allowed; ops' 20 pairs denied";
/// The stack's budget when the state names none (infra/budget.ts's name).
const DEFAULT_BUDGET: &str = "ai-env-monthly";

/// One `simulate-principal-policy` call: a principal's actions on resources,
/// every pair wanted allowed (the deployer's) or denied (ops').
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sim {
    pub principal: String,
    pub actions: &'static [&'static str],
    pub resources: Vec<String>,
    pub allowed: bool,
}

/// `arn:aws:iam::<12 digits>:user/<path/>name`.
fn is_user_arn(arn: &str) -> bool {
    arn.strip_prefix("arn:aws:iam::").and_then(|r| r.split_once(":user/")).is_some_and(|(acct, name)| acct.len() == 12 && acct.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty() && !name.ends_with('/'))
}

/// G7's eight calls (§8.1) from `state/infra.toml`; `Err` says what the
/// state lacks, or that its deployer is no IAM user (G7 is then skipped).
pub fn g7_plan(s: &InfraState) -> std::result::Result<Vec<Sim>, String> {
    let some = |v: &Option<String>| v.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
    let image = Some(s.image_arn.trim().to_string()).filter(|a| !a.is_empty());
    let fields = [("deployer_user_arn", some(&s.deployer_user_arn)), ("ops_user_arn", some(&s.ops_user_arn)), ("runtime_user_arn", some(&s.runtime_user_arn)), ("image_arn", image)];
    let lacking: Vec<&str> = fields.iter().filter(|(_, v)| v.is_none()).map(|(name, _)| *name).collect();
    if !lacking.is_empty() {
        return Err(format!("state/infra.toml lacks {}  <- make infra-status WRITE=1 after the bootstrap", lacking.join(", ")));
    }
    let [deployer, ops, runtime, image] = fields.map(|(_, v)| v.unwrap_or_default());
    if !is_user_arn(&deployer) {
        return Err(format!("deployer_user_arn {deployer:?} in state/infra.toml is not an IAM user ARN  <- make infra-status WRITE=1"));
    }
    let account = some(&s.account_id).or_else(|| arn_account(&deployer).map(str::to_string)).unwrap_or_default();
    let budget = some(&s.budget_name).unwrap_or_else(|| DEFAULT_BUDGET.to_string());
    let prefix = some(&s.parameter_prefix).unwrap_or_else(|| PARAMETER_PREFIX.to_string());
    let parameter = |name: &str| format!("arn:aws:ssm:{REGION}:{account}:parameter{prefix}/{name}");
    let sim = |principal: &str, actions: &'static [&'static str], resources: Vec<String>, allowed: bool| Sim { principal: principal.to_string(), actions, resources, allowed };
    Ok(vec![
        sim(&deployer, &["iam:CreateUser", "iam:CreateAccessKey"], vec![runtime.clone()], true),
        sim(&deployer, &["iam:CreateAccessKey"], vec![ops.clone()], true),
        sim(&deployer, &["budgets:ModifyBudget"], vec![format!("arn:aws:budgets::{account}:budget/{budget}")], true),
        sim(&ops, &["cloudformation:CreateResource", "cloudformation:UpdateResource", "cloudformation:DeleteResource", "lambda:CreateMicrovmImage"], vec!["*".to_string()], false),
        sim(&ops, &["iam:CreateAccessKey", "iam:PutUserPolicy", "iam:AttachUserPolicy"], vec![deployer.clone(), ops.clone(), runtime], false),
        sim(&ops, &["lambda:UpdateMicrovmImage", "lambda:UpdateMicrovmImageVersion", "lambda:DeleteMicrovmImageVersion"], vec![image], false),
        sim(&ops, &["ssm:PutParameter"], vec![parameter("extras"), parameter("allow"), parameter("squid.conf")], false),
        sim(&ops, &["ssm:SendCommand"], vec![format!("arn:aws:ssm:{REGION}::document/AWS-RunShellScript")], false),
    ])
}

/// The argv of one G7 call (after `aws`).
pub fn sim_args(s: &Sim) -> Vec<&str> {
    let mut args = vec!["iam", "simulate-principal-policy", "--region", REGION, "--policy-source-arn", s.principal.as_str(), "--action-names"];
    args.extend(s.actions.iter().copied());
    args.push("--resource-arns");
    args.extend(s.resources.iter().map(String::as_str));
    args.extend(["--output", "json"]);
    args
}

/// `(action, resource, decision)` of every pair a `simulate-principal-policy`
/// answer holds, flat (`EvalActionName`, `EvalResourceName`, `EvalDecision`)
/// or nested (`ResourceSpecificResults` of `EvalResourceName` and
/// `EvalResourceDecision`).
pub fn sim_decisions(json: &str) -> std::result::Result<Vec<(String, String, String)>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("unreadable simulate-principal-policy answer: {e}"))?;
    let results = v.get("EvaluationResults").and_then(|r| r.as_array()).ok_or("unreadable simulate-principal-policy answer: no EvaluationResults")?;
    let text = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let mut out = Vec::new();
    for r in results {
        let action = text(r, "EvalActionName");
        match r.get("ResourceSpecificResults").and_then(|x| x.as_array()).filter(|x| !x.is_empty()) {
            Some(nested) => out.extend(nested.iter().map(|n| (action.clone(), text(n, "EvalResourceName"), text(n, "EvalResourceDecision")))),
            None => out.push((action, text(r, "EvalResourceName"), text(r, "EvalDecision"))),
        }
    }
    Ok(out)
}

/// A resource as G7 shows it: the ARN's part after its fifth colon (`*` as it is).
fn shown_resource(arn: &str) -> &str {
    arn.splitn(6, ':').nth(5).unwrap_or(arn)
}

/// G7's verdict on its calls' answers (one per [`Sim`], in order): ✓ when
/// every requested pair is answered, every positive `allowed` and every
/// negative `implicitDeny` or `explicitDeny`; ? otherwise (a positive denied,
/// a negative allowed, a missing pair, an unreadable answer, a failed call).
pub fn g7_verdict(plan: &[Sim], answers: &[std::result::Result<String, String>]) -> (GateStatus, String) {
    let (mut deployer_pairs, mut errors) = (Vec::new(), Vec::new());
    let (mut denied, mut negatives) = (0usize, 0usize);
    let mut failing: Vec<(String, String)> = Vec::new();
    let (mut deployer, mut ops) = (String::new(), String::new());
    let mut pass = true;
    for (sim, answer) in plan.iter().zip(answers) {
        let decisions = match answer.as_deref().map_err(String::clone).and_then(sim_decisions) {
            Ok(d) => d,
            Err(e) => {
                if !errors.contains(&e) {
                    errors.push(e);
                }
                Vec::new()
            }
        };
        let who = shown_resource(&sim.principal).to_string();
        if sim.allowed { deployer.clone_from(&who) } else { ops.clone_from(&who) }
        for action in sim.actions {
            for resource in &sim.resources {
                let decision = decisions.iter().find(|(a, r, _)| a == action && r == resource).map(|(_, _, d)| d.as_str());
                let pair = format!("{action}@{}", shown_resource(resource));
                if sim.allowed {
                    pass &= decision == Some("allowed");
                    deployer_pairs.push(format!("{pair}={}", decision.unwrap_or("missing")));
                } else {
                    negatives += 1;
                    match decision {
                        Some("implicitDeny" | "explicitDeny") => denied += 1,
                        Some(other) => failing.push((other.to_string(), pair)),
                        None => failing.push(("missing".to_string(), pair)),
                    }
                }
            }
        }
    }
    pass &= denied == negatives && errors.is_empty() && answers.len() == plan.len();
    let mut observed = format!("deployer {deployer}: {}; ops {ops}: {denied}/{negatives} deploy actions denied", deployer_pairs.join(", "));
    let mut kinds: Vec<&str> = Vec::new();
    for (kind, _) in &failing {
        if !kinds.contains(&kind.as_str()) {
            kinds.push(kind);
        }
    }
    for kind in kinds {
        let pairs: Vec<&str> = failing.iter().filter(|(k, _)| k == kind).map(|(_, p)| p.as_str()).collect();
        observed.push_str(&format!("; {kind}: {}", pairs.join(", ")));
    }
    for e in errors {
        observed.push_str(&format!("; {e}"));
    }
    (if pass { GateStatus::Pass } else { GateStatus::Manual }, observed)
}

/// G7: the deployer's four pairs allowed and ops' twenty denied, simulated
/// for the stack's users of `state/infra.toml` as the operator identity
/// (`operator`: its resolution, `Err` the labelled refusal, which skips it).
fn g7(operator: Option<&std::result::Result<(), String>>) -> GateResult {
    let skipped = |why: String| gate("G7", G7_NAME, G7_COMMAND, G7_EXPECTED, why, GateStatus::Skipped);
    if let Some(Err(e)) = operator {
        return skipped(e.clone());
    }
    // A missing state lacks every field G7 needs.
    let state = match crate::bridge::config::Paths::resolve().map_err(|e| e.to_string()).and_then(|paths| read_infra_state(&paths).map_err(|e| e.to_string())) {
        Ok(state) => state.unwrap_or_default(),
        Err(e) => return skipped(format!("state/infra.toml unreadable: {e}  <- make infra-status WRITE=1")),
    };
    let plan = match g7_plan(&state) {
        Ok(plan) => plan,
        Err(why) => return skipped(why),
    };
    let answers: Vec<std::result::Result<String, String>> = plan.iter().map(|s| operator_capture(&sim_args(s), Duration::from_secs(30))).collect();
    let (status, observed) = g7_verdict(&plan, &answers);
    gate("G7", G7_NAME, G7_COMMAND, G7_EXPECTED, observed, status)
}

fn g8() -> GateResult {
    gate(
        "G8",
        "Touch ID from a GUI-spawned terminal",
        "Cursor integrated terminal → ai-env show on a test container",
        "LocalAuthentication dialog appears",
        "manual".into(),
        GateStatus::Manual,
    )
}

/// Does this run measure G2 or G7, the gates that need the operator identity?
fn needs_operator(only: &[String]) -> bool {
    only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case("G2") || o.eq_ignore_ascii_case("G7"))
}

/// Run every gate (or only the listed ids); `operator` is the identity's
/// resolution when G2 or G7 runs (`Err`: the labelled refusal). The boolean
/// reports that AWS credentials or an operator identity were unavailable
/// (exit 5 semantics).
#[must_use]
pub fn run_all(repo_root: &Path, only: &[String], operator: Option<&std::result::Result<(), String>>) -> (Vec<GateResult>, bool) {
    let wanted = |id: &str| only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case(id));
    let mut rows = Vec::new();
    if wanted("G1") {
        rows.push(g1(repo_root));
    }
    if wanted("G2") {
        rows.push(g2(operator));
    }
    if wanted("G3") {
        rows.push(g3(repo_root));
    }
    if wanted("G4") {
        rows.push(g4());
    }
    if wanted("G5") {
        rows.push(g5());
    }
    if wanted("G6") {
        rows.push(g6());
    }
    if wanted("G7") {
        rows.push(g7(operator));
    }
    if wanted("G8") {
        rows.push(g8());
    }
    let creds_unavailable = rows.iter().any(|r| {
        let observed = r.observed.to_ascii_lowercase();
        observed.contains("unable to locate credentials") || observed.contains("no aws operator identity")
    });
    (rows, creds_unavailable)
}

/// Gates whose verdict is (at least sometimes) recorded by hand: G4 without
/// a token, G5, G6's preview, G8. Every other gate is re-measured on every
/// run — a Manual G7 (an action denied) is the measurement, not a placeholder.
const HAND_RECORDED: [&str; 4] = ["G4", "G5", "G6", "G8"];

/// Gates whose Skipped row is itself the verdict: G7 is skipped when the
/// state or the operator identity it simulates as is missing or refused,
/// never a tool, and an older ✓ would claim a simulation this run never made
/// (§8.1: the reason is shown).
const SKIPPED_IS_MEASURED: [&str; 1] = ["G7"];

/// Hand-recorded gates that came back Manual, and any gate but G7 that came
/// back Skipped (the tool or binary to measure it is missing), take the
/// observed text, status and date recorded in the existing table — unless
/// that record is just the tool's own placeholder (empty, `…`, or exactly
/// what this run would write), in which case nobody recorded anything yet. A
/// row whose status was set to ✓/✗ by hand counts as recorded even with the
/// placeholder text. A skipped gate takes only a record of the same gate, its
/// id and name: a row of another name under that id measured something else.
/// Measured rows, G7's skipped one included, always take the fresh result.
#[must_use]
pub fn merge_manual(mut fresh: Vec<GateResult>, existing_md: Option<&str>) -> Vec<GateResult> {
    let Some(md) = existing_md else {
        return fresh;
    };
    let existing = parse(md);
    let names: std::collections::BTreeMap<String, String> = table(md).into_iter().map(|r| (r.0, r.1)).collect();
    for row in &mut fresh {
        let mergeable = match row.status {
            GateStatus::Manual => HAND_RECORDED.contains(&row.id),
            GateStatus::Skipped => !SKIPPED_IS_MEASURED.contains(&row.id) && names.get(row.id).is_some_and(|name| name == row.name),
            GateStatus::Pass | GateStatus::Fail => false,
        };
        if !mergeable {
            continue;
        }
        if let Some((observed, status, date)) = existing.get(row.id) {
            // Compared as written: the file holds the fresh text through `cell` (escaped, masked).
            let stock = observed.is_empty() || observed == "…" || cell(observed) == cell(&row.observed);
            let hand_recorded = !stock || matches!(status, GateStatus::Pass | GateStatus::Fail);
            if hand_recorded {
                row.observed = observed.clone();
                row.status = *status;
                row.date = date.clone();
            }
        }
    }
    fresh
}

/// `id → (observed, status, date)` from a rendered table.
#[must_use]
pub fn parse(md: &str) -> std::collections::BTreeMap<String, (String, GateStatus, String)> {
    table(md).into_iter().map(|(id, _, observed, status, date)| (id, (observed, status, date))).collect()
}

/// The rows of a rendered table, in order: `(id, name, observed, status,
/// date)`, the name being the Gate cell after the id.
fn table(md: &str) -> Vec<(String, String, String, GateStatus, String)> {
    let mut out = Vec::new();
    for line in md.lines() {
        if !line.starts_with("| G") {
            continue;
        }
        // `\|` inside a cell is an escaped pipe, not a column break.
        let protected = line.replace("\\|", "\u{0}");
        let cells: Vec<String> = protected.split('|').map(|c| c.trim().replace('\u{0}', "|")).collect();
        if cells.len() < 8 {
            continue;
        }
        let id = cells[1].split_whitespace().next().unwrap_or("").to_string();
        let name = cells[1][id.len()..].trim().to_string();
        let Some(status) = GateStatus::from_glyph(&cells[5]) else {
            continue;
        };
        out.push((id, name, cells[4].clone(), status, cells[6].clone()));
    }
    out
}

/// Free text after the go/no-go paragraph of an existing file (hand-written
/// status notes), carried over verbatim by `render`.
#[must_use]
pub fn trailer(existing_md: &str) -> Option<String> {
    let idx = existing_md.find("\n**Go/no-go:**")?;
    let after = &existing_md[idx + 1..];
    let end_of_para = after.find('\n')?;
    let rest = after[end_of_para + 1..].trim_matches('\n');
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

/// `s` with every run of exactly 12 ASCII digits, an AWS account id (in G7's
/// ARN, or in the aws CLI's text), replaced by `<acct>`; a longer or shorter
/// run of digits is left alone.
pub(crate) fn mask_account_ids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
        let end = rest[start..].find(|c: char| !c.is_ascii_digit()).map_or(rest.len(), |n| start + n);
        out.push_str(&rest[..start]);
        out.push_str(if end - start == 12 { "<acct>" } else { &rest[start..end] });
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// One table cell, safe in a Markdown preview: account ids masked
/// ([`mask_account_ids`]), then `<` and `>` outside code spans written
/// `&lt;` and `&gt;` (the aws CLI's `<AccessDeniedException>` is otherwise
/// raw HTML, which can drop the table), a pipe escaped and a newline a
/// space. A code span is a pair of single backticks, kept as is (an entity
/// in it would show as written); an unmatched backtick is literal text, and
/// what follows it is not code. A cell with a run of two or more backticks,
/// or a backslash before one, has no code span: a preview pairs those
/// otherwise, so every `<` and `>` in it is written as an entity. A cell
/// written so comes back unchanged (its pipes read back by [`parse`]), so a
/// row kept from the file stays verbatim.
fn cell(s: &str) -> String {
    let s = mask_account_ids(s);
    let ticks = s.matches('`').count();
    let spans = !s.contains("``") && !s.contains("\\`");
    let (mut seen, mut code) = (0, false);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '`' => {
                seen += 1;
                // The 1st, 3rd, … open a span, but the last of an odd count opens nothing.
                code = spans && seen % 2 == 1 && seen < ticks;
                out.push(c);
            }
            '<' if !code => out.push_str("&lt;"),
            '>' if !code => out.push_str("&gt;"),
            '|' => out.push_str("\\|"),
            '\n' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

#[must_use]
pub fn render(rows: &[GateResult], trailer: Option<&str>) -> String {
    let mut md = String::new();
    md.push_str("# Gates (G0) — MicroVM bridge\n\n");
    md.push_str(&format!(
        "Last run: {} (`ai-env gates` re-measures G1, G2, G7 and re-inspects the last `make vm-build` for G3; G4 without a token, G5, G6's preview and G8 are recorded by hand: replace the Observed cell with the evidence and set the Status glyph — the next run keeps any row whose text is not the tool's own placeholder. Notes below the go/no-go line are preserved too).\n\n",
        today()
    ));
    md.push_str("| Gate | Command | Expected | Observed | Status | Date |\n|---|---|---|---|---|---|\n");
    for r in rows {
        md.push_str(&format!(
            "| {} {} | {} | {} | {} | {} | {} |\n",
            r.id,
            r.name,
            // One code span: G1's `<repo>` in it is kept as is.
            cell(&format!("`{}`", r.command)),
            cell(&r.expected),
            cell(&r.observed),
            r.status.glyph(),
            r.date
        ));
    }
    md.push_str("\n**Go/no-go:** GO only if G1–G5 are all ✓. Any ✗ on G1–G5 → NO-GO: re-scope before S0 (G3 ✗ → glibc/musl fallback; G4 ✗ → mirror by tailing the VM projects dir; G5 ✗ → the credential design changes). G6–G8 are recorded either way and select documented fallbacks.\n");
    if let Some(t) = trailer {
        md.push('\n');
        md.push_str(t);
        md.push('\n');
    }
    md
}

/// 5 when credentials were unavailable, 1 when any blocking gate present in
/// `rows` is ✗ or still unrecorded, else 0. G6–G8 never affect the exit code.
#[must_use]
pub fn exit_code(rows: &[GateResult], creds_unavailable: bool) -> i32 {
    if creds_unavailable {
        return 5;
    }
    let blocked = rows.iter().any(|r| BLOCKING.contains(&r.id) && matches!(r.status, GateStatus::Fail | GateStatus::Manual | GateStatus::Skipped));
    if blocked {
        1
    } else {
        0
    }
}

/// The exit of a run whose operator identity was `refused` (labelled): the
/// higher of the rows' [`exit_code`] and the refusal's class, so a marker or
/// principal the resolver refuses is exit 9 and a missing keystore key exit
/// 4, as from every other operator command, where G2 and G7 only show it
/// (and `--only G7`, which never blocks, would exit 0).
#[must_use]
pub fn exit_with(exit: i32, refused: Option<&CliError>) -> i32 {
    refused.map_or(exit, |e| exit.max(e.exit_code()))
}

/// GO means every blocking gate is present and none blocks: a subset run can
/// exit 0 without being a GO.
#[must_use]
pub fn go(rows: &[GateResult], exit: i32) -> bool {
    exit == 0 && BLOCKING.iter().all(|b| rows.iter().any(|r| r.id == *b))
}

#[must_use]
pub fn to_json(rows: &[GateResult], exit: i32, partial: bool) -> String {
    let mut s = format!("{{\"go\":{},\"partial\":{partial},\"exit\":{exit},\"gates\":[", go(rows, exit));
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"id\":{},\"name\":{},\"status\":{},\"observed\":{},\"date\":{}}}",
            json_string(r.id),
            json_string(r.name),
            json_string(r.status.json_name()),
            json_string(&r.observed),
            json_string(&r.date)
        ));
    }
    s.push_str("]}");
    s
}

fn repo_root() -> PathBuf {
    run_capture("git", &["rev-parse", "--show-toplevel"], Duration::from_secs(5))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// The `ai-env gates` command.
pub fn main(json: bool, out: Option<PathBuf>, only: Vec<String>) -> Result<()> {
    let unknown = unknown_ids(&only);
    if !unknown.is_empty() {
        return Err(CliError::Usage(format!("unknown gate id(s) {}; known: {}", unknown.join(", "), KNOWN.join(", "))));
    }
    let partial = !only.is_empty();
    // S8 operators: the operator identity first, once (its Touch ID before any gate runs); a dismissed dialog
    // cancels the run, any other refusal is shown by G2 and G7 and keeps its class for the exit.
    let operator = needs_operator(&only).then(|| crate::bridge::identity::operator().map(|_| ()).map_err(|e| crate::bridge::identity::labelled("gates", e)));
    if let Some(Err(CliError::Cancelled)) = &operator {
        return Err(CliError::Cancelled);
    }
    let shown = operator.as_ref().map(|r| match r {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    });
    let refused = operator.and_then(std::result::Result::err);
    let root = repo_root();
    let path = out.unwrap_or_else(|| root.join("plans").join("gates.md"));
    let existing = std::fs::read_to_string(&path).ok();
    let (fresh, creds_unavailable) = run_all(&root, &only, shown.as_ref());
    let rows = merge_manual(fresh, existing.as_deref());
    let rows_exit = exit_code(&rows, creds_unavailable);
    let exit = exit_with(rows_exit, refused.as_ref());
    if !partial {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let keep = existing.as_deref().and_then(trailer);
        std::fs::write(&path, render(&rows, keep.as_deref()))?;
    }
    if json {
        outln!("{}", to_json(&rows, exit, partial));
    } else {
        for r in &rows {
            outln!("{} {:<4} {:<38} {}", r.status.glyph(), r.id, r.name, r.observed);
        }
        if partial {
            outln!("partial run (--only): go/no-go not evaluated; {} not written", path.display());
        } else {
            outln!("{}: {}", if go(&rows, exit) { "GO" } else { "NO-GO" }, path.display());
        }
    }
    if let Some(e) = refused.filter(|_| exit > rows_exit) {
        // The identity's refusal raised the exit: its own text and class.
        return Err(e);
    }
    match exit {
        0 => Ok(()),
        5 => Err(CliError::AuthUnavailable("aws credentials unavailable".into())),
        // A subset can fail (exit 1) without a verdict: go/no-go needs the full run.
        _ if partial => Err(CliError::Msg("a blocking gate in this subset is failed or unrecorded (go/no-go is not evaluated on --only)".into())),
        _ => Err(CliError::Msg("NO-GO: a blocking gate (G1–G5) is failed or unrecorded".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &'static str, status: GateStatus, observed: &str) -> GateResult {
        GateResult { id, name: "n", command: "c".into(), expected: "e".into(), observed: observed.into(), status, date: "2026-09-19".into() }
    }

    #[test]
    fn from_line_reads_the_pinned_base() {
        let df = "# comment\n# FROM not-this\nFROM public.ecr.aws/lambda/microvms:al2023-minimal@sha256:00 AS base\nRUN true\nFROM other\n";
        assert_eq!(from_line(df).as_deref(), Some("public.ecr.aws/lambda/microvms:al2023-minimal@sha256:00"));
        assert_eq!(from_line("RUN true\n"), None);
        let repo = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/Dockerfile")).unwrap();
        let base = from_line(&repo).unwrap();
        assert!(base.starts_with(BASE_TAG) && base.contains("@sha256:"), "the image is digest-pinned: {base}");
    }

    #[test]
    fn render_parse_roundtrip() {
        let rows = vec![row("G1", GateStatus::Pass, "rustc 1.98.1"), row("G5", GateStatus::Manual, "manual: interactive login"), row("G8", GateStatus::Skipped, "x | y")];
        let md = render(&rows, None);
        let parsed = parse(&md);
        assert_eq!(parsed["G1"].0, "rustc 1.98.1");
        assert_eq!(parsed["G1"].1, GateStatus::Pass);
        assert_eq!(parsed["G8"].0, "x | y");
        assert_eq!(parsed["G8"].1, GateStatus::Skipped);
    }

    /// G2's Observed on 11 Oct 2026: the aws CLI's `<AccessDeniedException>`
    /// is written as entities, never as raw HTML (which a Markdown preview
    /// swallows, and in some the table with it).
    #[test]
    fn a_cell_writes_the_aws_clis_angle_brackets_as_entities() {
        let g2 = "eu-central-1: al2023-1 listed; eu-west-3: aws: [ERROR]: An error occurred (403) when calling the ListManagedMicrovmImages operation: <AccessDeniedException>";
        assert_eq!(cell(g2), "eu-central-1: al2023-1 listed; eu-west-3: aws: [ERROR]: An error occurred (403) when calling the ListManagedMicrovmImages operation: &lt;AccessDeniedException&gt;");
    }

    /// G7's Observed on 11 Oct 2026 named the account in an ARN: a run of
    /// exactly 12 digits is masked anywhere in a cell (in a code span too,
    /// where `<acct>` stays as it is); 11 or 13 digits are no account id.
    #[test]
    fn a_cell_masks_account_ids() {
        let g7 = "aws: [ERROR]: An error occurred (InvalidInput) when calling the SimulatePrincipalPolicy operation: Invalid ARN provided in the request: arn:aws:iam::123456789012:root";
        assert_eq!(cell(g7), "aws: [ERROR]: An error occurred (InvalidInput) when calling the SimulatePrincipalPolicy operation: Invalid ARN provided in the request: arn:aws:iam::&lt;acct&gt;:root");
        assert_eq!(cell("arn:aws:iam::123456789012:user/example: iam:CreateUser=allowed"), "arn:aws:iam::&lt;acct&gt;:user/example: iam:CreateUser=allowed");
        assert_eq!(cell("123456789012"), "&lt;acct&gt;", "the whole cell");
        assert_eq!(cell("`123456789012`"), "`<acct>`", "in a code span");
        for kept in ["1234567890123 ms", "after 12345678901 ms", "rustc 1.98.1 (48a229cea 2026-09-01)"] {
            assert_eq!(cell(kept), kept);
        }
    }

    /// A code span (a pair of single backticks) is kept as is; an unmatched
    /// backtick is literal, and what follows it is not code. A pipe is
    /// escaped everywhere, in a code span too, and a newline is a space.
    #[test]
    fn a_cell_keeps_code_spans_and_escapes_pipes() {
        assert_eq!(cell("ran `claude <x>` once"), "ran `claude <x>` once");
        assert_eq!(cell("`<a>` then ` <b>"), "`<a>` then ` &lt;b&gt;", "the third backtick is unmatched");
        assert_eq!(cell("a ` <b> c"), "a ` &lt;b&gt; c");
        assert_eq!(cell("`<b>``"), "`&lt;b&gt;``", "a run of two closes no single backtick");
        assert_eq!(cell("\\`<b>`"), "\\`&lt;b&gt;`", "an escaped backtick opens no span");
        assert_eq!(cell("x | `y | z`"), "x \\| `y \\| z`");
        assert_eq!(cell("a\nb"), "a b");
    }

    /// The command is one code span: G1's `<repo>` in it is kept as is, and
    /// the pipe in G2's is escaped, as before.
    #[test]
    fn render_writes_the_command_as_one_code_span() {
        let mut g1 = row("G1", GateStatus::Pass, "ok");
        g1.command = "cargo +1.98.1 fetch --locked --quiet --manifest-path <repo>/Cargo.toml".into();
        let mut g2 = row("G2", GateStatus::Pass, "ok");
        g2.command = "aws lambda-microvms list-managed-microvm-images --region eu-central-1 | --region eu-west-3".into();
        let md = render(&[g1, g2], None);
        assert!(md.contains("| G1 n | `cargo +1.98.1 fetch --locked --quiet --manifest-path <repo>/Cargo.toml` | e | ok | ✓ | 2026-09-19 |\n"), "{md}");
        assert!(md.contains("| G2 n | `aws lambda-microvms list-managed-microvm-images --region eu-central-1 \\| --region eu-west-3` | e | ok | ✓ | 2026-09-19 |\n"), "{md}");
    }

    /// A row kept from the file (a hand record, or a skipped gate's last
    /// one) is written back verbatim: a code span keeps its `<…>`, an entity
    /// is not escaped again, a pipe is read back and escaped again.
    #[test]
    fn a_kept_row_is_written_back_verbatim() {
        let hand = "ran `ai-env lab run touchid-gui <from Cursor>` | prompted; aws said &lt;AccessDeniedException&gt;";
        let md = render(&[row("G8", GateStatus::Pass, hand)], None);
        let line = "| G8 n | `c` | e | ran `ai-env lab run touchid-gui <from Cursor>` \\| prompted; aws said &lt;AccessDeniedException&gt; | ✓ | 2026-09-19 |";
        assert!(md.lines().any(|l| l == line), "{md}");
        let merged = merge_manual(vec![row("G8", GateStatus::Manual, "manual")], Some(&md));
        assert_eq!((merged[0].observed.as_str(), merged[0].status), (hand, GateStatus::Pass), "a record, read back");
        assert_eq!(render(&merged, None), md, "and written back as it was");
    }

    /// A skipped gate keeps its last record, but no account id in it: a
    /// record an older ai-env wrote unmasked is masked on the way out (here
    /// G3's, the binary gone). The tool's own skipped text, escaped in the
    /// file, is still its placeholder: today's row, not the old one.
    #[test]
    fn a_kept_record_is_masked_and_the_tools_own_text_is_no_record() {
        let pulled = "docker: pulled 123456789012.dkr.ecr.eu-central-1.amazonaws.com/base; ai-env 0.1.0";
        let unmasked = render(&[row("G3", GateStatus::Manual, "x")], None).replace("| x |", &format!("| {pulled} |"));
        let skipped = row("G3", GateStatus::Skipped, "image/ai-env missing — run: make vm-build (<repo>/image/ai-env)");
        let merged = merge_manual(vec![skipped.clone()], Some(&unmasked));
        assert_eq!((merged[0].observed.as_str(), merged[0].status), (pulled, GateStatus::Manual), "the last record");
        let md = render(&merged, None);
        assert!(md.contains("| docker: pulled &lt;acct&gt;.dkr.ecr.eu-central-1.amazonaws.com/base; ai-env 0.1.0 |") && !md.contains("123456789012"), "{md}");
        let mut today = skipped.clone();
        today.date = "2026-10-12".into();
        let merged = merge_manual(vec![today], Some(&render(&[skipped], None)));
        assert_eq!((merged[0].status, merged[0].date.as_str()), (GateStatus::Skipped, "2026-10-12"), "the tool's own text is no record");
    }

    #[test]
    fn merge_keeps_hand_records_and_drops_placeholders() {
        // The tool's own placeholder from an earlier run (older date): not a record.
        let mut g8_old = row("G8", GateStatus::Manual, "manual");
        g8_old.date = "2026-09-01".into();
        let existing = render(
            &[
                row("G5", GateStatus::Pass, "result frame seen; remote-control refused"),
                row("G1", GateStatus::Fail, "old failure"),
                // A hand note that happens to start with "manual" is still a record.
                row("G4", GateStatus::Manual, "manual: needs the G5 token — run ai-env gates --only G4 with it"),
                g8_old,
                // Placeholder text but a hand-set status: a record.
                row("G6", GateStatus::Pass, "aws-native 1.79.0 installed; preview recorded by hand"),
            ],
            None,
        );
        let fresh = vec![
            row("G1", GateStatus::Pass, "fresh"),
            row("G4", GateStatus::Manual, "manual: set AI_ENV_CLAUDE_TESTS=1 and CLAUDE_CODE_OAUTH_TOKEN to automate"),
            row("G5", GateStatus::Manual, "manual: interactive login"),
            row("G6", GateStatus::Manual, "aws-native 1.79.0 installed; preview recorded by hand"),
            row("G8", GateStatus::Manual, "manual"),
        ];
        let merged = merge_manual(fresh, Some(&existing));
        assert_eq!((merged[0].observed.as_str(), merged[0].status), ("fresh", GateStatus::Pass), "automated rows are always fresh");
        assert!(merged[1].observed.starts_with("manual: needs the G5 token"), "{}", merged[1].observed);
        assert_eq!((merged[2].observed.as_str(), merged[2].status), ("result frame seen; remote-control refused", GateStatus::Pass));
        assert_eq!(merged[3].status, GateStatus::Pass, "hand-set status on placeholder text is a record");
        assert_eq!((merged[4].observed.as_str(), merged[4].date.as_str()), ("manual", "2026-09-19"), "placeholder stays fresh (today's date, not the old record's)");
        // A measured gate that came back Manual (G7: an action denied) is a measurement, never merged.
        let existing = render(&[row("G7", GateStatus::Pass, "arn:aws:iam::123456789012:user/example: iam:CreateUser=allowed")], None);
        let merged = merge_manual(vec![row("G7", GateStatus::Manual, "arn:aws:iam::123456789012:user/example: iam:CreateUser=implicitDeny")], Some(&existing));
        assert_eq!(merged[0].status, GateStatus::Manual, "G7 is re-measured on every run");
        assert!(merged[0].observed.contains("implicitDeny"));
        // Stale binary after `make clean`: the skipped G3 takes the last inspection.
        let existing = render(&[row("G3", GateStatus::Pass, "ELF aarch64; max GLIBC_2.30; getentropy refs 0; docker: ai-env 0.1.0")], None);
        let merged = merge_manual(vec![row("G3", GateStatus::Skipped, "image/ai-env missing — run: make vm-build")], Some(&existing));
        assert_eq!(merged[0].status, GateStatus::Pass);
        let merged = merge_manual(vec![row("G3", GateStatus::Skipped, "image/ai-env missing — run: make vm-build")], Some(&render(&[row("G3", GateStatus::Skipped, "image/ai-env missing — run: make vm-build")], None)));
        assert_eq!(merged[0].status, GateStatus::Skipped);
    }

    #[test]
    fn trailer_survives_a_rerun() {
        let md = render(&[row("G1", GateStatus::Pass, "ok")], Some("**Status 2026-09-19:** G4 and G5 wait for Mike.\n\nSecond paragraph."));
        assert_eq!(trailer(&md).as_deref(), Some("**Status 2026-09-19:** G4 and G5 wait for Mike.\n\nSecond paragraph."));
        assert_eq!(trailer(&render(&[row("G1", GateStatus::Pass, "ok")], None)), None);
        assert_eq!(trailer("no table at all"), None);
    }

    #[test]
    fn exit_codes_and_go() {
        let pass: Vec<GateResult> = ["G1", "G2", "G3", "G4", "G5"].iter().map(|id| row(id, GateStatus::Pass, "ok")).collect();
        assert_eq!(exit_code(&pass, false), 0);
        assert!(go(&pass, 0));
        let mut with_g8 = pass.clone();
        with_g8.push(row("G8", GateStatus::Manual, "manual"));
        assert_eq!(exit_code(&with_g8, false), 0, "G6–G8 never block");
        assert!(go(&with_g8, 0));
        let mut manual5 = pass.clone();
        manual5[4].status = GateStatus::Manual;
        assert_eq!(exit_code(&manual5, false), 1);
        assert!(!go(&manual5, 1));
        assert_eq!(exit_code(&pass, true), 5);
        assert!(!go(&pass, 5));
        let subset = vec![row("G1", GateStatus::Pass, "ok")];
        assert_eq!(exit_code(&subset, false), 0, "the subset passed");
        assert!(!go(&subset, 0), "but a subset is never a GO");
        let g8_only = vec![row("G8", GateStatus::Manual, "manual")];
        assert!(!go(&g8_only, exit_code(&g8_only, false)));
    }

    /// S8 operators: a refused operator identity keeps its class, as from
    /// every other operator command (a marker or principal the resolver
    /// refuses 9, a missing keystore key 4), where the rows alone would give
    /// 0 (G7 never blocks) or 1; the rows' own exit stands when it is higher
    /// or there is no refusal.
    #[test]
    fn a_refused_identity_keeps_its_class_in_the_exit() {
        let policy = CliError::Policy("gates: AI_ENV_BRIDGE_AS=root, but …".into());
        assert_eq!(exit_with(0, Some(&policy)), 9, "--only G7: skipped, yet refused");
        assert_eq!(exit_with(1, Some(&policy)), 9, "a full run: G2 ✗ from the same refusal");
        assert_eq!(exit_with(1, Some(&CliError::NoKey("gates: key".into()))), 4);
        assert_eq!(exit_with(5, Some(&CliError::AuthUnavailable("gates: no AWS operator identity: …".into()))), 5);
        assert_eq!(exit_with(1, Some(&CliError::Msg("gates: aws sts get-caller-identity: …".into()))), 1);
        assert_eq!((exit_with(0, None), exit_with(1, None), exit_with(5, None)), (0, 1, 5));
        let all: Vec<GateResult> = BLOCKING.iter().map(|id| row(id, GateStatus::Pass, "ok")).collect();
        assert!(!go(&all, exit_with(0, Some(&policy))), "never a GO under a refused identity");
    }

    /// A skipped gate takes the last record of its own gate only: a row of
    /// another name under its id measured something else, so the skipped
    /// text, status and date stand; a record of the same gate is still kept.
    #[test]
    fn a_skipped_gate_never_takes_the_record_of_another_gate_under_its_id() {
        let skipped = GateResult { name: "cross build on AL2023 arm64", date: "2026-10-14".into(), ..row("G3", GateStatus::Skipped, "image/ai-env missing — run: make vm-build") };
        let other = GateResult { name: "an earlier gate under that id", ..row("G3", GateStatus::Pass, "measured something else") };
        let merged = merge_manual(vec![skipped.clone()], Some(&render(&[other], None)));
        assert_eq!(merged, std::slice::from_ref(&skipped), "the fresh skipped row, as measured");
        let recorded = GateResult { observed: "ELF aarch64; max GLIBC_2.30; getentropy refs 0".into(), status: GateStatus::Pass, date: "2026-10-13".into(), ..skipped.clone() };
        let merged = merge_manual(vec![skipped], Some(&render(std::slice::from_ref(&recorded), None)));
        assert_eq!((merged[0].observed.as_str(), merged[0].status, merged[0].date.as_str()), (recorded.observed.as_str(), GateStatus::Pass, "2026-10-13"), "its own last record");
    }

    /// A skipped G7 never takes a record, not even its own: it is skipped
    /// when the state or the identity to simulate as is missing or refused,
    /// never a tool, and an older ✓ would claim a simulation this run never
    /// made (§8.1: the row shows why). Nor does G7's row of before S8
    /// operators (another name, the caller simulated) count.
    #[test]
    fn a_skipped_g7_shows_why_over_any_record() {
        let mut skipped = gate("G7", G7_NAME, G7_COMMAND, G7_EXPECTED, "state/infra.toml lacks deployer_user_arn, ops_user_arn  <- make infra-status WRITE=1 after the bootstrap".into(), GateStatus::Skipped);
        skipped.date = "2026-10-14".into();
        let old = GateResult {
            name: "IAM for the runtime principal",
            ..row("G7", GateStatus::Manual, "aws: [ERROR]: An error occurred (InvalidInput) when calling the SimulatePrincipalPolicy operation: Invalid ARN provided in the request: `arn:aws:iam::<acct>:root`")
        };
        let recorded = GateResult { observed: "deployer user/ai-env-deployer: …; ops user/ai-env-ops: 20/20 deploy actions denied".into(), status: GateStatus::Pass, date: "2026-10-13".into(), ..skipped.clone() };
        let hand = GateResult { observed: "simulated by hand in the console".into(), status: GateStatus::Pass, ..recorded.clone() };
        for file in [render(&[old], None), render(std::slice::from_ref(&recorded), None), render(&[hand], None)] {
            assert_eq!(merge_manual(vec![skipped.clone()], Some(&file)), std::slice::from_ref(&skipped), "the fresh skipped row:\n{file}");
        }
        let names: Vec<(String, String)> = table(&render(&[recorded], None)).into_iter().map(|r| (r.0, r.1)).collect();
        assert_eq!(names, [("G7".to_string(), G7_NAME.to_string())], "its own record, which it still never takes");
    }

    #[test]
    fn json_shape() {
        let s = to_json(&[row("G1", GateStatus::Pass, "ok")], 0, true);
        assert!(s.starts_with("{\"go\":false,\"partial\":true,\"exit\":0,\"gates\":[{\"id\":\"G1\""), "{s}");
        let all: Vec<GateResult> = BLOCKING.iter().map(|id| row(id, GateStatus::Pass, "ok")).collect();
        assert!(to_json(&all, 0, false).starts_with("{\"go\":true,\"partial\":false,"));
    }

    #[test]
    fn unknown_ids_are_reported() {
        assert!(unknown_ids(&["g1".into(), "G8".into()]).is_empty());
        assert_eq!(unknown_ids(&["G9".into(), "G1".into(), "x".into()]), vec!["G9".to_string(), "x".to_string()]);
    }

    #[test]
    fn getentropy_is_counted_on_the_versioned_symbol() {
        let nm = "                 U getentropy@GLIBC_2.25\n                 U getrandom@GLIBC_2.25\n0000000000001234 T main\n                 U getentropy\n";
        assert_eq!(count_getentropy(nm), 2);
        assert_eq!(count_getentropy("                 U getrandom@GLIBC_2.25\n"), 0);
        assert_eq!(count_getentropy(""), 0);
    }

    #[test]
    fn glibc_ceiling_is_the_max_minor() {
        let objdump = "DYNAMIC SYMBOL TABLE:\n0000000000000000      DF *UND* 0000000000000000 (GLIBC_2.17) memcpy\n0000000000000000      DF *UND* 0000000000000000 (GLIBC_2.30) getdents64\n0000000000000000      DF *UND* 0000000000000000 (GLIBC_2.2.5) free\n";
        assert_eq!(max_glibc_minor(objdump), Some(30));
        assert_eq!(max_glibc_minor("nothing here"), None);
    }

    #[test]
    fn pulumi_plugin_listing() {
        let json = "[{\"name\":\"aws\",\"kind\":\"resource\",\"version\":\"7.10.0\"},{\"name\":\"aws-native\",\"kind\":\"resource\",\"version\":\"1.79.0\",\"size\":95000000}]";
        assert!(plugin_listed(json, "aws-native", "resource", "1.79.0"));
        assert!(!plugin_listed(json, "aws-native", "resource", "1.80.0"));
        assert!(!plugin_listed("not json", "aws-native", "resource", "1.79.0"));
        assert!(plugin_listed("[{\"name\":\"aws-native\",\"kind\":\"resource\",\"version\":\"v1.79.0\"}]", "aws-native", "resource", "1.79.0"));
    }

    #[test]
    fn stale_inputs_compare_mtimes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("crates").join("ai-env-cli").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "x").unwrap();
        std::fs::write(src.join("lib.rs"), "x").unwrap();
        let later = SystemTime::now() + Duration::from_secs(60);
        assert!(stale_inputs(dir.path(), later).is_empty());
        let earlier = SystemTime::now() - Duration::from_secs(60);
        assert_eq!(stale_inputs(dir.path(), earlier), vec!["Cargo.lock".to_string(), "crates/ai-env-cli/src".to_string()]);
    }

    #[test]
    fn glyphs_roundtrip() {
        for st in [GateStatus::Pass, GateStatus::Fail, GateStatus::Manual, GateStatus::Skipped] {
            assert_eq!(GateStatus::from_glyph(st.glyph()), Some(st));
        }
    }

    const STACK: &str = "123456789012";

    fn user(name: &str) -> String {
        format!("arn:aws:iam::{STACK}:user/{name}")
    }

    /// The operator fields of `state/infra.toml` after the bootstrap.
    fn operator_state() -> InfraState {
        InfraState {
            account_id: Some(STACK.into()),
            image_arn: format!("arn:aws:lambda:eu-central-1:{STACK}:microvm-image:ai-env-agent"),
            deployer_user_arn: Some(user("ai-env-deployer")),
            ops_user_arn: Some(user("ai-env-ops")),
            runtime_user_arn: Some(user("ai-env-runtime")),
            ..InfraState::default()
        }
    }

    /// An answer to `s` in the flat shape (one result per action and
    /// resource) or the nested one (`ResourceSpecificResults`), each pair's
    /// decision from `decide`.
    fn answer(s: &Sim, nested: bool, decide: &dyn Fn(&str, &str) -> &'static str) -> String {
        let results: Vec<serde_json::Value> = if nested {
            s.actions
                .iter()
                .map(|a| {
                    let per: Vec<serde_json::Value> = s.resources.iter().map(|r| serde_json::json!({"EvalResourceName": r, "EvalResourceDecision": decide(a, r)})).collect();
                    serde_json::json!({"EvalActionName": a, "EvalResourceName": "*", "EvalDecision": "implicitDeny", "ResourceSpecificResults": per})
                })
                .collect()
        } else {
            s.actions.iter().flat_map(|a| s.resources.iter().map(move |r| serde_json::json!({"EvalActionName": a, "EvalResourceName": r, "EvalDecision": decide(a, r), "MatchedStatements": []}))).collect()
        };
        serde_json::json!({"EvaluationResults": results}).to_string()
    }

    /// S8 operators §8.1: eight calls, the deployer's four pairs on their own
    /// resources and ops' twenty deploy actions, from the stack's users (never
    /// the caller's ARN), the account and names from the state.
    #[test]
    fn g7_plan_simulates_the_deployer_per_resource_and_the_ops_negatives() {
        let plan = g7_plan(&operator_state()).unwrap();
        assert_eq!(plan.len(), 8);
        let pairs = |allowed: bool| plan.iter().filter(|s| s.allowed == allowed).map(|s| s.actions.len() * s.resources.len()).sum::<usize>();
        assert_eq!((pairs(true), pairs(false)), (4, 20));
        assert!(plan[..3].iter().all(|s| s.allowed && s.principal == user("ai-env-deployer")), "{plan:?}");
        assert!(plan[3..].iter().all(|s| !s.allowed && s.principal == user("ai-env-ops")), "{plan:?}");
        assert_eq!(
            sim_args(&plan[0]),
            ["iam", "simulate-principal-policy", "--region", "eu-central-1", "--policy-source-arn", &user("ai-env-deployer"), "--action-names", "iam:CreateUser", "iam:CreateAccessKey", "--resource-arns", &user("ai-env-runtime"), "--output", "json"]
        );
        assert_eq!(plan[1].resources, [user("ai-env-ops")]);
        assert_eq!(plan[2].resources, [format!("arn:aws:budgets::{STACK}:budget/ai-env-monthly")]);
        assert_eq!(plan[3].resources, ["*"]);
        assert_eq!(plan[4].resources, [user("ai-env-deployer"), user("ai-env-ops"), user("ai-env-runtime")]);
        assert_eq!(plan[5].resources, [operator_state().image_arn]);
        let param = |p: &str| format!("arn:aws:ssm:eu-central-1:{STACK}:parameter/ai-env/proxy/{p}");
        assert_eq!(plan[6].resources, [param("extras"), param("allow"), param("squid.conf")]);
        assert_eq!(plan[7].resources, ["arn:aws:ssm:eu-central-1::document/AWS-RunShellScript"]);
        // The budget and the prefix the state records; the account of the deployer's ARN without account_id.
        let named = InfraState { account_id: None, budget_name: Some("b2".into()), parameter_prefix: Some("/x/proxy".into()), ..operator_state() };
        let plan = g7_plan(&named).unwrap();
        assert_eq!(plan[2].resources, [format!("arn:aws:budgets::{STACK}:budget/b2")]);
        assert_eq!(plan[6].resources[0], format!("arn:aws:ssm:eu-central-1:{STACK}:parameter/x/proxy/extras"));
        // What the state lacks skips G7, named; a deployer that is no IAM user too.
        let e = g7_plan(&InfraState { ops_user_arn: None, image_arn: String::new(), ..operator_state() }).unwrap_err();
        assert_eq!(e, "state/infra.toml lacks ops_user_arn, image_arn  <- make infra-status WRITE=1 after the bootstrap");
        let e = g7_plan(&InfraState::default()).unwrap_err();
        assert!(e.starts_with("state/infra.toml lacks deployer_user_arn, ops_user_arn, runtime_user_arn, image_arn"), "{e}");
        for bad in [format!("arn:aws:iam::{STACK}:root"), format!("arn:aws:sts::{STACK}:assumed-role/a/b"), format!("arn:aws:iam::{STACK}:user/")] {
            let e = g7_plan(&InfraState { deployer_user_arn: Some(bad.clone()), ..operator_state() }).unwrap_err();
            assert!(e.contains("is not an IAM user ARN"), "{bad}: {e}");
        }
    }

    /// ✓ needs every pair answered, the four positives allowed and the twenty
    /// negatives denied, in either answer shape; anything else is ?, naming
    /// the pairs that fail.
    #[test]
    fn g7_verdict_reads_both_answer_shapes_and_needs_every_pair() {
        let plan = g7_plan(&operator_state()).unwrap();
        // The deployer's actions overlap ops' (iam:CreateAccessKey): a decision is the call's, never the action's.
        let by_call = |nested: bool| -> Vec<std::result::Result<String, String>> { plan.iter().map(|s| Ok(answer(s, nested, &|_, _| if s.allowed { "allowed" } else { "implicitDeny" }))).collect() };
        let want = "deployer user/ai-env-deployer: iam:CreateUser@user/ai-env-runtime=allowed, iam:CreateAccessKey@user/ai-env-runtime=allowed, iam:CreateAccessKey@user/ai-env-ops=allowed, budgets:ModifyBudget@budget/ai-env-monthly=allowed; ops user/ai-env-ops: 20/20 deploy actions denied";
        for nested in [false, true] {
            assert_eq!(g7_verdict(&plan, &by_call(nested)), (GateStatus::Pass, want.to_string()), "nested {nested}");
        }
        // An explicit deny is a deny.
        let explicit: Vec<std::result::Result<String, String>> = plan.iter().map(|s| Ok(answer(s, false, &|_, _| if s.allowed { "allowed" } else { "explicitDeny" }))).collect();
        assert_eq!(g7_verdict(&plan, &explicit).0, GateStatus::Pass);
        // Ops may put the extras parameter: ?, the pair named.
        let mut leaky = by_call(false);
        leaky[6] = Ok(answer(&plan[6], false, &|_, r| if r.ends_with("/extras") { "allowed" } else { "implicitDeny" }));
        let (status, observed) = g7_verdict(&plan, &leaky);
        assert_eq!(status, GateStatus::Manual);
        assert!(observed.ends_with("ops user/ai-env-ops: 19/20 deploy actions denied; allowed: ssm:PutParameter@parameter/ai-env/proxy/extras"), "{observed}");
        // A positive denied, and an answer missing a pair.
        let mut denied = by_call(false);
        denied[2] = Ok(answer(&plan[2], false, &|_, _| "implicitDeny"));
        denied[7] = Ok("{\"EvaluationResults\": []}".to_string());
        let (status, observed) = g7_verdict(&plan, &denied);
        assert_eq!(status, GateStatus::Manual);
        assert!(observed.contains("budgets:ModifyBudget@budget/ai-env-monthly=implicitDeny") && observed.contains("19/20 deploy actions denied; missing: ssm:SendCommand@document/AWS-RunShellScript"), "{observed}");
        // A failed call or an unreadable answer: ?, its error named, its pairs missing.
        let mut failed = by_call(false);
        failed[0] = Err("An error occurred (AccessDenied) when calling the SimulatePrincipalPolicy operation: denied".into());
        failed[3] = Ok("not json".into());
        let (status, observed) = g7_verdict(&plan, &failed);
        assert_eq!(status, GateStatus::Manual);
        assert!(observed.contains("iam:CreateUser@user/ai-env-runtime=missing") && observed.contains("16/20 deploy actions denied; missing: cloudformation:CreateResource@*"), "{observed}");
        assert!(observed.contains("; An error occurred (AccessDenied)") && observed.contains("; unreadable simulate-principal-policy answer"), "{observed}");
        // In gates.md the account ids are masked (cell).
        assert!(!cell(&format!("{observed} {}", user("x"))).contains(STACK));
    }
}
