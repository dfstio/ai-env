//! `ai-env gates` — the G1–G8 pre-code gates of the MicroVM plan. G1, G2, G7
//! are re-measured on every run; G3 re-inspects the last `make vm-build`
//! output (it never rebuilds it); G6 checks the plugin and leaves the preview
//! to a hand record. Manual rows (G4 without a token, G5, G6, G8) and skipped
//! rows keep whatever the existing `plans/gates.md` records, unless that text
//! is the tool's own placeholder. GO requires G1–G5 ✓ on a full run;
//! `--only` never evaluates go/no-go and never writes the file.
use crate::bridge::doctor::{capture, run_capture};
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

fn g2() -> GateResult {
    let t = Duration::from_secs(30);
    if run_capture("aws", &["--version"], Duration::from_secs(5)).is_err() {
        return gate("G2", "region + API", "aws lambda-microvms list-managed-microvm-images", "al2023-1 listed / eu-west-3 403", "aws cli not found".into(), GateStatus::Skipped);
    }
    let central = run_capture("aws", &["lambda-microvms", "list-managed-microvm-images", "--region", "eu-central-1", "--output", "json"], t);
    let west = run_capture("aws", &["lambda-microvms", "list-managed-microvm-images", "--region", "eu-west-3", "--output", "json"], t);
    let central_ok = central.as_ref().is_ok_and(|j| j.contains("al2023-1"));
    let west_403 = west.as_ref().is_err_and(|e| e.contains("403") || e.contains("AccessDenied"));
    let obs = format!(
        "eu-central-1: {}; eu-west-3: {}",
        match &central {
            Ok(_) if central_ok => "al2023-1 listed".to_string(),
            Ok(j) => format!("unexpected: {}", j.chars().take(80).collect::<String>()),
            Err(e) => e.clone(),
        },
        match &west {
            Err(e) => e.clone(),
            Ok(_) => "unexpectedly succeeded".to_string(),
        }
    );
    gate(
        "G2",
        "region + API",
        "aws lambda-microvms list-managed-microvm-images --region eu-central-1 | --region eu-west-3",
        "al2023-1 listed / 403",
        obs,
        if central_ok && west_403 { GateStatus::Pass } else { GateStatus::Fail },
    )
}

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
    let docker = run_capture(
        "docker",
        &["run", "--rm", "--platform", "linux/arm64", "--entrypoint", "/b/ai-env", "-v", &format!("{dir}:/b:ro"), "public.ecr.aws/lambda/microvms:al2023-minimal", "--version"],
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
    let dirs: Vec<String> = std::fs::read_dir(&ext_dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
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

fn g7() -> GateResult {
    let cmd = "aws iam simulate-principal-policy … iam:CreateUser iam:CreateAccessKey budgets:ModifyBudget";
    let expected = "recorded either way (denied ⇒ named-profile fallback)";
    let arn = run_capture("aws", &["sts", "get-caller-identity", "--query", "Arn", "--output", "text"], Duration::from_secs(20));
    let Ok(arn) = arn else {
        return gate("G7", "IAM for the runtime principal", cmd, expected, format!("no identity: {}", arn.err().unwrap_or_default()), GateStatus::Skipped);
    };
    let sim = run_capture(
        "aws",
        &["iam", "simulate-principal-policy", "--policy-source-arn", &arn, "--action-names", "iam:CreateUser", "iam:CreateAccessKey", "budgets:ModifyBudget", "--output", "json"],
        Duration::from_secs(30),
    );
    match sim {
        Ok(json) => {
            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
            let mut parts = Vec::new();
            let mut all_allowed = true;
            for r in v.get("EvaluationResults").and_then(|r| r.as_array()).into_iter().flatten() {
                let a = r.get("EvalActionName").and_then(|x| x.as_str()).unwrap_or("?");
                let d = r.get("EvalDecision").and_then(|x| x.as_str()).unwrap_or("?");
                all_allowed &= d == "allowed";
                parts.push(format!("{a}={d}"));
            }
            gate("G7", "IAM for the runtime principal", cmd, expected, format!("{arn}: {}", parts.join(", ")), if all_allowed { GateStatus::Pass } else { GateStatus::Manual })
        }
        Err(e) => gate("G7", "IAM for the runtime principal", cmd, expected, e, GateStatus::Manual),
    }
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

/// Run every gate (or only the listed ids). The boolean reports that AWS
/// credentials were unavailable (exit 5 semantics).
#[must_use]
pub fn run_all(repo_root: &Path, only: &[String]) -> (Vec<GateResult>, bool) {
    let wanted = |id: &str| only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case(id));
    let mut rows = Vec::new();
    if wanted("G1") {
        rows.push(g1(repo_root));
    }
    if wanted("G2") {
        rows.push(g2());
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
        rows.push(g7());
    }
    if wanted("G8") {
        rows.push(g8());
    }
    let creds_unavailable = rows.iter().any(|r| r.observed.to_ascii_lowercase().contains("unable to locate credentials"));
    (rows, creds_unavailable)
}

/// Gates whose verdict is (at least sometimes) recorded by hand: G4 without
/// a token, G5, G6's preview, G8. Every other gate is re-measured on every
/// run — a Manual G7 (an action denied) is the measurement, not a placeholder.
const HAND_RECORDED: [&str; 4] = ["G4", "G5", "G6", "G8"];

/// Hand-recorded gates that came back Manual, and any gate that came back
/// Skipped (the tool or binary to measure it is missing), take the observed
/// text, status and date recorded in the existing table — unless that record
/// is just the tool's own placeholder (empty, `…`, or exactly what this run
/// would write), in which case nobody recorded anything yet. A row whose
/// status was set to ✓/✗ by hand counts as recorded even with the placeholder
/// text. Measured rows always take the fresh measurement.
#[must_use]
pub fn merge_manual(mut fresh: Vec<GateResult>, existing_md: Option<&str>) -> Vec<GateResult> {
    let Some(md) = existing_md else {
        return fresh;
    };
    let existing = parse(md);
    for row in &mut fresh {
        let mergeable = match row.status {
            GateStatus::Manual => HAND_RECORDED.contains(&row.id),
            GateStatus::Skipped => true,
            GateStatus::Pass | GateStatus::Fail => false,
        };
        if !mergeable {
            continue;
        }
        if let Some((observed, status, date)) = existing.get(row.id) {
            let stock = observed.is_empty() || observed == "…" || *observed == row.observed;
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
    let mut out = std::collections::BTreeMap::new();
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
        let Some(status) = GateStatus::from_glyph(&cells[5]) else {
            continue;
        };
        out.insert(id, (cells[4].clone(), status, cells[6].clone()));
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

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
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
            "| {} {} | `{}` | {} | {} | {} | {} |\n",
            r.id,
            r.name,
            cell(&r.command),
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
    let root = repo_root();
    let path = out.unwrap_or_else(|| root.join("plans").join("gates.md"));
    let existing = std::fs::read_to_string(&path).ok();
    let (fresh, creds_unavailable) = run_all(&root, &only);
    let rows = merge_manual(fresh, existing.as_deref());
    let exit = exit_code(&rows, creds_unavailable);
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
    fn render_parse_roundtrip() {
        let rows = vec![row("G1", GateStatus::Pass, "rustc 1.98.1"), row("G5", GateStatus::Manual, "manual: interactive login"), row("G8", GateStatus::Skipped, "x | y")];
        let md = render(&rows, None);
        let parsed = parse(&md);
        assert_eq!(parsed["G1"].0, "rustc 1.98.1");
        assert_eq!(parsed["G1"].1, GateStatus::Pass);
        assert_eq!(parsed["G8"].0, "x | y");
        assert_eq!(parsed["G8"].1, GateStatus::Skipped);
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
}
