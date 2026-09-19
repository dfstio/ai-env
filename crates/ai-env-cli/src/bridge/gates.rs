//! `ai-env gates` — the G1–G8 pre-code gates of the MicroVM plan. Automated
//! rows are re-measured on every run; manual rows (G5, G8, and G4 without a
//! token in the environment) keep whatever the existing `plans/gates.md`
//! records. GO requires G1–G5 ✓.
use crate::bridge::doctor::run_capture;
use crate::commands::json_string;
use crate::errors::{CliError, Result};
use crate::outln;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

fn shell_ok(cmd: &str, timeout: Duration) -> std::result::Result<String, String> {
    run_capture("/bin/sh", &["-c", cmd], timeout)
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
    let fetch = shell_ok(&format!("cd {} && cargo +1.98.1 fetch --locked 2>&1 | tail -1", sh_quote(repo_root)), Duration::from_secs(600));
    match fetch {
        Ok(_) => obs.push("cargo fetch --locked ok".into()),
        Err(e) => {
            ok = false;
            obs.push(format!("cargo fetch: {e}"));
        }
    }
    gate(
        "G1",
        "toolchain + SDK fetch",
        "rustup run 1.98.1 rustc --version; rustup +1.98.1 target list --installed; cargo +1.98.1 fetch --locked",
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
    let cmd = "make vm-build; file; llvm-objdump -T; llvm-nm -D; docker run … al2023-minimal";
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
    let glibc = shell_ok(&format!("{} -T {} | grep -o 'GLIBC_2\\.[0-9]*' | sort -u -t. -k2,2n | tail -1", llvm_tool("llvm-objdump"), sh_quote(&bin)), Duration::from_secs(20)).unwrap_or_default();
    let minor: u32 = glibc.trim_start_matches("GLIBC_2.").parse().unwrap_or(999);
    if minor <= 34 {
        obs.push(format!("max {glibc}"));
    } else {
        ok = false;
        obs.push(format!("glibc ceiling exceeded: {glibc}"));
    }
    let ge = shell_ok(&format!("{} -D {} | grep -c ' getentropy$' || true", llvm_tool("llvm-nm"), sh_quote(&bin)), Duration::from_secs(20)).unwrap_or_default();
    if ge.trim() == "0" {
        obs.push("getentropy refs 0".into());
    } else {
        ok = false;
        obs.push(format!("getentropy refs {}", ge.trim()));
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
    gate("G3", "cross build on AL2023 arm64", cmd, expected, obs.join("; "), if ok { GateStatus::Pass } else { GateStatus::Fail })
}

fn g4() -> GateResult {
    let cmd = "bundled claude -p --output-format stream-json --input-format stream-json --verbose --session-mirror (one message)";
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
    let msg = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"Reply with the single word pong.\"}]}}";
    let script = format!(
        "printf '%s\\n' '{msg}' | CLAUDE_CONFIG_DIR={} CLAUDE_CODE_OAUTH_TOKEN=\"$G4_TOKEN\" {} -p --output-format stream-json --input-format stream-json --verbose --session-mirror",
        sh_quote(tmp.path()),
        sh_quote(&bin)
    );
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .env("G4_TOKEN", &token)
        .output();
    let observed = match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let mirrors = text.lines().filter(|l| l.contains("\"type\":\"transcript_mirror\"")).count();
            let results = text.lines().filter(|l| l.contains("\"type\":\"result\"")).count();
            let under_tmp = text.contains(&format!("{}/projects/", tmp.path().to_string_lossy()));
            let status = if mirrors >= 1 && results == 1 && under_tmp { GateStatus::Pass } else { GateStatus::Fail };
            return gate("G4", "--session-mirror on the bundled CLI", cmd, expected, format!("claude {ver}: {mirrors} transcript_mirror, {results} result, filePath under tmp: {under_tmp}"), status);
        }
        Err(e) => e.to_string(),
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
    let cmd = "pulumi plugin install resource aws-native 1.79.0; pulumi preview (aws-native:region=eu-central-1)";
    let expected = "plugin listed; preview passes";
    match run_capture("pulumi", &["plugin", "ls", "--json"], Duration::from_secs(20)) {
        Err(e) if e.contains("No such file") || e.contains("not found") => gate("G6", "aws-native plugin", cmd, expected, "pulumi not found".into(), GateStatus::Skipped),
        Err(e) => gate("G6", "aws-native plugin", cmd, expected, e, GateStatus::Fail),
        Ok(json) => {
            let has = json.contains("aws-native") && json.contains("1.79.0");
            gate(
                "G6",
                "aws-native plugin",
                cmd,
                expected,
                if has { "aws-native 1.79.0 installed (preview: manual)".into() } else { "aws-native 1.79.0 not installed".into() },
                if has { GateStatus::Pass } else { GateStatus::Fail },
            )
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

fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
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

/// Manual/skipped rows keep the observed text, status and date from an
/// existing table; automated rows always take the fresh measurement.
#[must_use]
pub fn merge_manual(mut fresh: Vec<GateResult>, existing_md: Option<&str>) -> Vec<GateResult> {
    let Some(md) = existing_md else {
        return fresh;
    };
    let existing = parse(md);
    for row in &mut fresh {
        if matches!(row.status, GateStatus::Manual | GateStatus::Skipped) {
            if let Some((observed, status, date)) = existing.get(row.id) {
                if !observed.is_empty() && !observed.starts_with("manual") && *observed != "…" {
                    row.observed = observed.clone();
                    row.status = *status;
                    row.date = date.clone();
                }
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

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[must_use]
pub fn render(rows: &[GateResult]) -> String {
    let mut md = String::new();
    md.push_str("# Gates (G0) — MicroVM bridge\n\n");
    md.push_str(&format!(
        "Last run: {} (`ai-env gates` regenerates automated rows; G5, G8 and G4 without a token are recorded by hand and preserved).\n\n",
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
    md
}

/// 5 when credentials were unavailable, 1 when any blocking gate is ✗ or still
/// unrecorded, else 0. G6–G8 never affect the exit code.
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

#[must_use]
pub fn to_json(rows: &[GateResult], exit: i32) -> String {
    let mut s = format!("{{\"go\":{},\"exit\":{exit},\"gates\":[", exit == 0);
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
    let root = repo_root();
    let path = out.unwrap_or_else(|| root.join("plans").join("gates.md"));
    let existing = std::fs::read_to_string(&path).ok();
    let (fresh, creds_unavailable) = run_all(&root, &only);
    let rows = merge_manual(fresh, existing.as_deref());
    let exit = exit_code(&rows, creds_unavailable);
    if only.is_empty() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, render(&rows))?;
    }
    if json {
        outln!("{}", to_json(&rows, exit));
    } else {
        for r in &rows {
            outln!("{} {:<4} {:<38} {}", r.status.glyph(), r.id, r.name, r.observed);
        }
        if only.is_empty() {
            outln!("written: {}", path.display());
        }
    }
    match exit {
        0 => Ok(()),
        5 => Err(CliError::AuthUnavailable("aws credentials unavailable".into())),
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
        let md = render(&rows);
        let parsed = parse(&md);
        assert_eq!(parsed["G1"].0, "rustc 1.98.1");
        assert_eq!(parsed["G1"].1, GateStatus::Pass);
        assert_eq!(parsed["G8"].0, "x | y");
        assert_eq!(parsed["G8"].1, GateStatus::Skipped);
    }

    #[test]
    fn merge_keeps_manual_records() {
        let existing = render(&[row("G5", GateStatus::Pass, "result frame seen; remote-control refused"), row("G1", GateStatus::Fail, "old failure")]);
        let fresh = vec![row("G1", GateStatus::Pass, "fresh"), row("G5", GateStatus::Manual, "manual: interactive login")];
        let merged = merge_manual(fresh, Some(&existing));
        assert_eq!(merged[0].observed, "fresh");
        assert_eq!(merged[0].status, GateStatus::Pass);
        assert_eq!(merged[1].observed, "result frame seen; remote-control refused");
        assert_eq!(merged[1].status, GateStatus::Pass);
    }

    #[test]
    fn exit_codes() {
        let pass: Vec<GateResult> = ["G1", "G2", "G3", "G4", "G5"].iter().map(|id| row(id, GateStatus::Pass, "ok")).collect();
        assert_eq!(exit_code(&pass, false), 0);
        let mut with_g8 = pass.clone();
        with_g8.push(row("G8", GateStatus::Manual, "manual"));
        assert_eq!(exit_code(&with_g8, false), 0, "G6–G8 never block");
        let mut manual5 = pass.clone();
        manual5[4].status = GateStatus::Manual;
        assert_eq!(exit_code(&manual5, false), 1);
        assert_eq!(exit_code(&pass, true), 5);
    }

    #[test]
    fn json_shape() {
        let s = to_json(&[row("G1", GateStatus::Pass, "ok")], 0);
        assert!(s.starts_with("{\"go\":true,\"exit\":0,\"gates\":[{\"id\":\"G1\""), "{s}");
    }

    #[test]
    fn glyphs_roundtrip() {
        for st in [GateStatus::Pass, GateStatus::Fail, GateStatus::Manual, GateStatus::Skipped] {
            assert_eq!(GateStatus::from_glyph(st.glyph()), Some(st));
        }
    }
}
