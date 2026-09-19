//! Bridge rows appended to `ai-env doctor`. Every row builder is a pure
//! function of already-collected inputs so it is unit-testable without the
//! subprocesses that `rows` runs (5 s timeout each).
use crate::age_cmd::{effective_path, find_in_path};
use crate::bridge::config::{env_region_warning, BridgeConfig, Paths, REGION};
use crate::bridge::errors::BridgeError;
use crate::bridge::sibling::{find_sibling, Sibling, INSTALL_HINT};
use crate::commands::{DoctorLine, Tag};
use crate::store::Keystore;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const EXPECTED_TOOLCHAIN: &str = "1.98.1";
/// cargo-lambda below this embeds a cargo-zigbuild that cannot link aarch64
/// on rustc ≥ 1.9x (`--fix-cortex-a53-843419`), measured 19 Sep 2026.
pub const MIN_CARGO_LAMBDA: (u32, u32, u32) = (1, 9, 2);
pub const WRAPPER_SETTING: &str = "claudeCode.claudeProcessWrapper";
pub const PERMISSION_SETTING: &str = "claudeCode.initialPermissionMode";
const NODE_SUFFIXES: [&str; 5] = [".js", ".mjs", ".ts", ".tsx", ".jsx"];

/// Run a command with a wall-clock timeout; `Ok(stdout)` on exit 0, else the
/// first stderr line (or the spawn/timeout error).
pub fn run_capture(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{program}: timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("{program}: {e}")),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err.trim().lines().next().unwrap_or("").to_string())
    }
}

/// First `x.y.z` token in a version banner.
#[must_use]
pub fn version_token(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',')
        .map(|t| t.trim_start_matches('v'))
        .find(|t| {
            let parts: Vec<&str> = t.split('.').collect();
            parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        })
        .map(str::to_string)
}

fn semver(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.split('.').map(|p| p.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

// ---- pure row builders ---------------------------------------------------------

#[must_use]
pub fn row_toolchain(rustc_out: Option<&str>) -> DoctorLine {
    match rustc_out.and_then(version_token) {
        Some(v) if v == EXPECTED_TOOLCHAIN => DoctorLine::row(Tag::Ok, format!("toolchain rustc {v}")),
        Some(v) => DoctorLine::row(Tag::Warn, format!("toolchain rustc {v} (expected {EXPECTED_TOOLCHAIN})")),
        None => DoctorLine::row(Tag::Skip, format!("rustup toolchain {EXPECTED_TOOLCHAIN} not found (dev only)")),
    }
}

#[must_use]
pub fn row_cross_tools(cargo_lambda_out: Option<&str>, zig_out: Option<&str>) -> DoctorLine {
    let zig = zig_out.and_then(version_token).unwrap_or_else(|| "zig missing".to_string());
    match cargo_lambda_out.and_then(version_token) {
        Some(v) => match semver(&v) {
            Some(t) if t >= MIN_CARGO_LAMBDA => DoctorLine::row(Tag::Ok, format!("cargo-lambda {v}, zig {zig} (make vm-build)")),
            _ => DoctorLine::row(
                Tag::Warn,
                format!(
                    "cargo-lambda {v} < {}.{}.{} — arm64 link fails on rustc 1.9x; upgrade: cargo install cargo-lambda --locked",
                    MIN_CARGO_LAMBDA.0, MIN_CARGO_LAMBDA.1, MIN_CARGO_LAMBDA.2
                ),
            ),
        },
        None => DoctorLine::row(Tag::Skip, "cargo-lambda not found (needed for make vm-build)"),
    }
}

/// `(row, credentials_unavailable)`.
#[must_use]
pub fn row_aws_identity(sts: Option<Result<&str, &str>>, env_warning: Option<&str>) -> (DoctorLine, bool) {
    match sts {
        None => (DoctorLine::row(Tag::Skip, "aws cli not found (bridge commands need it)"), false),
        Some(Err(msg)) => {
            let lower = msg.to_ascii_lowercase();
            let creds = lower.contains("credential") || lower.contains("expiredtoken") || lower.contains("invalidclienttokenid") || lower.contains("token");
            if creds {
                (DoctorLine::row(Tag::No, format!("aws credentials unavailable: {msg}")), true)
            } else {
                (DoctorLine::row(Tag::No, format!("aws identity: {msg}")), false)
            }
        }
        Some(Ok(json)) => {
            let arn = serde_json::from_str::<serde_json::Value>(json)
                .ok()
                .and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string))
                .unwrap_or_else(|| "unknown principal".to_string());
            let mut text = format!("aws identity {arn}, region {REGION} (pinned)");
            if let Some(w) = env_warning {
                text.push_str("  <- ");
                text.push_str(w);
            }
            (DoctorLine::row(Tag::Ok, text), false)
        }
    }
}

#[must_use]
pub fn row_iam_simulate(sim_json: Option<&str>) -> DoctorLine {
    let Some(json) = sim_json else {
        return DoctorLine::row(Tag::Skip, "iam simulate not run (no aws identity)");
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return DoctorLine::row(Tag::Skip, "iam simulate: unparseable output");
    };
    let mut denied = Vec::new();
    let mut allowed = Vec::new();
    for r in v.get("EvaluationResults").and_then(|r| r.as_array()).into_iter().flatten() {
        let action = r.get("EvalActionName").and_then(|a| a.as_str()).unwrap_or("?").to_string();
        if r.get("EvalDecision").and_then(|d| d.as_str()) == Some("allowed") {
            allowed.push(action);
        } else {
            denied.push(action);
        }
    }
    if denied.is_empty() && !allowed.is_empty() {
        DoctorLine::row(Tag::Ok, format!("{} allowed (dedicated runtime principal possible)", allowed.join(", ")))
    } else if !denied.is_empty() {
        DoctorLine::row(Tag::Skip, format!("iam simulate: {} denied — named-profile fallback", denied.join(", ")))
    } else {
        DoctorLine::row(Tag::Skip, "iam simulate: no results")
    }
}

#[must_use]
pub fn row_bridge_config(paths: &Paths, loaded: &Result<Option<BridgeConfig>, BridgeError>) -> DoctorLine {
    match loaded {
        Ok(Some(_)) => DoctorLine::row(Tag::Ok, format!("bridge.toml {}", paths.config.display())),
        Ok(None) => DoctorLine::row(
            Tag::Skip,
            format!("bridge.toml not found at {} (bridge not configured; classic commands unaffected)", paths.config.display()),
        ),
        Err(e) => DoctorLine::row(Tag::No, format!("bridge.toml: {e}")),
    }
}

#[must_use]
pub fn row_keystore_key(exists: bool, key: &str) -> DoctorLine {
    if exists {
        DoctorLine::row(Tag::Ok, format!("keystore key {key}"))
    } else {
        DoctorLine::row(Tag::Skip, format!("keystore key {key} absent  <- ai-env keygen {key}"))
    }
}

/// Highest `anthropic.claude-code-<semver>-darwin-arm64` directory name.
#[must_use]
pub fn pick_bundle(dirs: &[String]) -> Option<(String, String)> {
    dirs.iter()
        .filter_map(|d| {
            let rest = d.strip_prefix("anthropic.claude-code-")?;
            let ver = rest.strip_suffix("-darwin-arm64")?;
            semver(ver).map(|t| (t, ver.to_string(), d.clone()))
        })
        .max_by_key(|(t, _, _)| *t)
        .map(|(_, ver, dir)| (ver, dir))
}

#[must_use]
pub fn row_cursor_bundle(dirs: &[String], bundled_version: Option<&str>) -> DoctorLine {
    match pick_bundle(dirs) {
        Some((ver, _)) => {
            let n = dirs.iter().filter(|d| d.starts_with("anthropic.claude-code-")).count();
            let bundled = bundled_version.and_then(version_token).unwrap_or_else(|| "unknown".to_string());
            let mut text = format!("cursor extension {ver}, bundled claude {bundled}");
            if n > 1 {
                text.push_str(&format!(" ({n} versions installed)"));
            }
            DoctorLine::row(Tag::Ok, text)
        }
        None => DoctorLine::row(Tag::Skip, "Cursor Claude extension not found under ~/.cursor/extensions"),
    }
}

#[must_use]
pub fn row_path_claude(path_claude: Option<(&Path, &str)>, bundled_version: Option<&str>) -> DoctorLine {
    let bundled = bundled_version.and_then(version_token);
    match path_claude {
        None => DoctorLine::row(Tag::Skip, "no claude on PATH (the wrapper uses the bundled binary)"),
        Some((p, out)) => {
            let v = version_token(out).unwrap_or_else(|| "unknown".to_string());
            match &bundled {
                Some(b) if *b != v => DoctorLine::row(Tag::Warn, format!("claude on PATH {v} ({}) ≠ bundled {b}", p.display())),
                _ => DoctorLine::row(Tag::Ok, format!("claude on PATH {v} ({})", p.display())),
            }
        }
    }
}

#[must_use]
pub fn row_sibling(s: &Sibling) -> DoctorLine {
    match s {
        Sibling::Next(p) => DoctorLine::row(Tag::Ok, format!("ai-env-claude next to ai-env ({})", p.display())),
        Sibling::PathOnly(p) => DoctorLine::row(Tag::Ok, format!("ai-env-claude on PATH only ({})  <- note: the sibling next to ai-env is preferred", p.display())),
        Sibling::Missing => DoctorLine::row(Tag::No, format!("ai-env-claude missing  <- {INSTALL_HINT}")),
    }
}

#[must_use]
pub fn row_same_version(sibling_version_out: Option<&str>, mine: &str) -> DoctorLine {
    match sibling_version_out.and_then(version_token) {
        Some(v) if v == mine => DoctorLine::row(Tag::Ok, format!("same version {mine}")),
        Some(v) => DoctorLine::row(Tag::No, format!("version skew: ai-env {mine}, ai-env-claude {v}  <- {INSTALL_HINT}")),
        None => DoctorLine::row(Tag::Skip, "ai-env-claude --version not available"),
    }
}

/// Rows for Cursor's wrapper setting; `exists_exec(path) -> (exists, executable)`.
#[must_use]
pub fn row_wrapper_setting(settings: Option<&serde_json::Value>, exists_exec: &dyn Fn(&Path) -> (bool, bool), sibling: &Sibling) -> Vec<DoctorLine> {
    let mut rows = Vec::new();
    let wrapper = settings.and_then(|s| s.get(WRAPPER_SETTING)).and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    match wrapper {
        None => rows.push(DoctorLine::row(Tag::Skip, format!("{WRAPPER_SETTING} not set (ai-env wrapper install, S1)"))),
        Some(p) => {
            let path = Path::new(p);
            let (exists, exec) = exists_exec(path);
            if !exists {
                rows.push(DoctorLine::row(Tag::No, format!("{WRAPPER_SETTING} = {p} does not exist")));
            } else if !exec {
                rows.push(DoctorLine::row(Tag::No, format!("{WRAPPER_SETTING} = {p} is not executable")));
            } else {
                rows.push(DoctorLine::row(Tag::Ok, format!("{WRAPPER_SETTING} = {p}")));
            }
            if NODE_SUFFIXES.iter().any(|s| p.ends_with(s)) {
                rows.push(DoctorLine::row(Tag::Warn, "wrapper path ends in a JS/TS suffix: Cursor would run it under node (extensionless bin required)"));
            }
            if let Sibling::Next(sib) | Sibling::PathOnly(sib) = sibling {
                if sib != path {
                    rows.push(DoctorLine::row(Tag::Warn, format!("wrapper points elsewhere than the sibling ({})", sib.display())));
                }
            }
        }
    }
    if settings.and_then(|s| s.get(PERMISSION_SETTING)).and_then(|v| v.as_str()).is_none() {
        rows.push(DoctorLine::row(Tag::Skip, format!("{PERMISSION_SETTING} unset (sessions start in Manual mode)")));
    }
    rows
}

/// Cursor writes JSON with `//` comments; strip whole-line comments.
#[must_use]
pub fn parse_settings(text: &str) -> Option<serde_json::Value> {
    let cleaned: String = text.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    serde_json::from_str(&cleaned).ok()
}

// ---- collection ------------------------------------------------------------------

pub struct BridgeDoctor {
    pub lines: Vec<DoctorLine>,
    pub auth_unavailable: bool,
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

fn exists_exec(p: &Path) -> (bool, bool) {
    let Ok(meta) = std::fs::metadata(p) else {
        return (false, false);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return (true, meta.permissions().mode() & 0o111 != 0);
    }
    #[allow(unreachable_code)]
    (true, meta.is_file())
}

/// Collect the inputs and build every bridge row.
#[must_use]
pub fn rows(store: &Keystore) -> BridgeDoctor {
    let t = Duration::from_secs(5);
    let mut lines = Vec::new();

    lines.push(row_toolchain(run_capture("rustup", &["run", EXPECTED_TOOLCHAIN, "rustc", "--version"], t).ok().as_deref()));
    lines.push(row_cross_tools(
        run_capture("cargo-lambda", &["lambda", "--version"], t).ok().as_deref(),
        run_capture("zig", &["version"], t).ok().as_deref(),
    ));

    let aws_present = find_in_path("aws", &effective_path()).is_some();
    let sts = if aws_present {
        Some(run_capture("aws", &["sts", "get-caller-identity", "--region", REGION, "--output", "json"], Duration::from_secs(15)))
    } else {
        None
    };
    let env_warning = env_region_warning();
    let (row, auth_unavailable) = row_aws_identity(sts.as_ref().map(|r| r.as_deref().map_err(String::as_str)), env_warning.as_deref());
    lines.push(row);
    let arn = sts.as_ref().and_then(|r| r.as_ref().ok()).and_then(|json| {
        serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string))
    });
    let sim = arn.and_then(|arn| {
        run_capture(
            "aws",
            &["iam", "simulate-principal-policy", "--policy-source-arn", &arn, "--action-names", "iam:CreateUser", "iam:CreateAccessKey", "--output", "json"],
            Duration::from_secs(15),
        )
        .ok()
    });
    lines.push(row_iam_simulate(sim.as_deref()));

    match Paths::resolve() {
        Ok(paths) => {
            let loaded = BridgeConfig::load(&paths);
            lines.push(row_bridge_config(&paths, &loaded));
        }
        Err(e) => lines.push(DoctorLine::row(Tag::No, format!("bridge paths: {e}"))),
    }
    lines.push(row_keystore_key(store.key_exists("ai-env-bridge"), "ai-env-bridge"));

    let ext_dir = home().join(".cursor").join("extensions");
    let dirs: Vec<String> = std::fs::read_dir(&ext_dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    let bundled_out = pick_bundle(&dirs).and_then(|(_, dir)| {
        let bin = ext_dir.join(dir).join("resources").join("native-binary").join("claude");
        run_capture(&bin.to_string_lossy(), &["--version"], t).ok()
    });
    lines.push(row_cursor_bundle(&dirs, bundled_out.as_deref()));
    let path_claude = find_in_path("claude", &effective_path());
    let path_out = path_claude.as_ref().and_then(|p| run_capture(&p.to_string_lossy(), &["--version"], t).ok());
    lines.push(row_path_claude(path_claude.as_deref().zip(path_out.as_deref()), bundled_out.as_deref()));

    let sibling = find_sibling("ai-env-claude");
    lines.push(row_sibling(&sibling));
    let sib_out = match &sibling {
        Sibling::Next(p) | Sibling::PathOnly(p) => run_capture(&p.to_string_lossy(), &["--version"], t).ok(),
        Sibling::Missing => None,
    };
    lines.push(row_same_version(sib_out.as_deref(), env!("CARGO_PKG_VERSION")));

    let settings_path = home().join("Library").join("Application Support").join("Cursor").join("User").join("settings.json");
    let settings = std::fs::read_to_string(&settings_path).ok().and_then(|t| parse_settings(&t));
    lines.extend(row_wrapper_setting(settings.as_ref(), &exists_exec, &sibling));

    BridgeDoctor { lines, auth_unavailable }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(l: &DoctorLine) -> (Tag, String) {
        match l {
            DoctorLine::Row { tag, text } => (*tag, text.clone()),
            DoctorLine::Plain(t) => (Tag::Skip, t.clone()),
        }
    }

    #[test]
    fn version_tokens() {
        assert_eq!(version_token("cargo-lambda 1.9.2 (2026-09-19Z)"), Some("1.9.2".into()));
        assert_eq!(version_token("rustc 1.98.1 (48a229cea 2026-09-01)"), Some("1.98.1".into()));
        assert_eq!(version_token("2.1.278 (Claude Code)"), Some("2.1.278".into()));
        assert_eq!(version_token("0.16.0"), Some("0.16.0".into()));
        assert_eq!(version_token("nope"), None);
    }

    #[test]
    fn toolchain_and_cross_tools() {
        assert_eq!(text(&row_toolchain(Some("rustc 1.98.1 (x)"))).0, Tag::Ok);
        assert_eq!(text(&row_toolchain(Some("rustc 1.90.0 (x)"))).0, Tag::Warn);
        assert_eq!(text(&row_toolchain(None)).0, Tag::Skip);
        assert_eq!(text(&row_cross_tools(Some("cargo-lambda 1.9.2 (d)"), Some("0.16.0"))).0, Tag::Ok);
        let (tag, t) = text(&row_cross_tools(Some("cargo-lambda 1.9.1 (d)"), Some("0.16.0")));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("1.9.1 < 1.9.2"), "{t}");
        assert_eq!(text(&row_cross_tools(None, None)).0, Tag::Skip);
    }

    #[test]
    fn aws_identity_rows() {
        let (r, u) = row_aws_identity(None, None);
        assert_eq!((text(&r).0, u), (Tag::Skip, false));
        let (r, u) = row_aws_identity(Some(Err("Unable to locate credentials. You can configure credentials by running \"aws configure\".")), None);
        assert_eq!((text(&r).0, u), (Tag::No, true));
        let (r, u) = row_aws_identity(Some(Ok("{\"Arn\":\"arn:aws:iam::058264205854:user/rust\"}")), Some("env AWS_REGION=eu-west-3 ignored (region pinned to eu-central-1)"));
        let (tag, t) = text(&r);
        assert_eq!((tag, u), (Tag::Ok, false));
        assert!(t.contains("user/rust") && t.contains("eu-central-1 (pinned)") && t.contains("eu-west-3 ignored"), "{t}");
    }

    #[test]
    fn iam_rows() {
        let allowed = "{\"EvaluationResults\":[{\"EvalActionName\":\"iam:CreateUser\",\"EvalDecision\":\"allowed\"},{\"EvalActionName\":\"iam:CreateAccessKey\",\"EvalDecision\":\"allowed\"}]}";
        assert_eq!(text(&row_iam_simulate(Some(allowed))).0, Tag::Ok);
        let denied = "{\"EvaluationResults\":[{\"EvalActionName\":\"iam:CreateUser\",\"EvalDecision\":\"implicitDeny\"}]}";
        let (tag, t) = text(&row_iam_simulate(Some(denied)));
        assert_eq!(tag, Tag::Skip);
        assert!(t.contains("named-profile fallback"), "{t}");
        assert_eq!(text(&row_iam_simulate(None)).0, Tag::Skip);
    }

    #[test]
    fn config_and_key_rows() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        assert_eq!(text(&row_bridge_config(&p, &Ok(None))).0, Tag::Skip);
        assert_eq!(text(&row_bridge_config(&p, &Ok(Some(BridgeConfig::default())))).0, Tag::Ok);
        assert_eq!(text(&row_bridge_config(&p, &Err(BridgeError::Config("bad".into())))).0, Tag::No);
        assert_eq!(text(&row_keystore_key(false, "ai-env-bridge")).0, Tag::Skip);
        assert_eq!(text(&row_keystore_key(true, "ai-env-bridge")).0, Tag::Ok);
    }

    #[test]
    fn cursor_rows() {
        let dirs: Vec<String> = ["anthropic.claude-code-2.1.274-darwin-arm64", "anthropic.claude-code-2.1.278-darwin-arm64", "anthropic.claude-code-2.1.276-darwin-arm64", "other.ext-1.0.0"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(pick_bundle(&dirs).unwrap().0, "2.1.278");
        let (tag, t) = text(&row_cursor_bundle(&dirs, Some("2.1.278 (Claude Code)")));
        assert_eq!(tag, Tag::Ok);
        assert!(t.contains("cursor extension 2.1.278, bundled claude 2.1.278 (3 versions installed)"), "{t}");
        assert_eq!(text(&row_cursor_bundle(&[], None)).0, Tag::Skip);
        let (tag, t) = text(&row_path_claude(Some((Path::new("/opt/homebrew/bin/claude"), "2.1.267 (Claude Code)")), Some("2.1.278 (Claude Code)")));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("2.1.267") && t.contains("≠ bundled 2.1.278"), "{t}");
        assert_eq!(text(&row_path_claude(Some((Path::new("/x"), "2.1.278 (Claude Code)")), Some("2.1.278 (Claude Code)"))).0, Tag::Ok);
        assert_eq!(text(&row_path_claude(None, None)).0, Tag::Skip);
    }

    #[test]
    fn sibling_and_version_rows() {
        assert_eq!(text(&row_sibling(&Sibling::Next(PathBuf::from("/b/ai-env-claude")))).0, Tag::Ok);
        assert_eq!(text(&row_sibling(&Sibling::PathOnly(PathBuf::from("/p/ai-env-claude")))).0, Tag::Ok);
        let (tag, t) = text(&row_sibling(&Sibling::Missing));
        assert_eq!(tag, Tag::No);
        assert!(t.contains(INSTALL_HINT));
        assert_eq!(text(&row_same_version(Some("ai-env-claude 0.1.0"), "0.1.0")).0, Tag::Ok);
        assert_eq!(text(&row_same_version(Some("ai-env-claude 0.0.9"), "0.1.0")).0, Tag::No);
        assert_eq!(text(&row_same_version(None, "0.1.0")).0, Tag::Skip);
    }

    #[test]
    fn wrapper_setting_rows() {
        let sib = Sibling::Next(PathBuf::from("/Users/mike/.cargo/bin/ai-env-claude"));
        let none = row_wrapper_setting(None, &|_| (false, false), &sib);
        assert_eq!(text(&none[0]).0, Tag::Skip);
        assert!(text(&none[1]).1.contains(PERMISSION_SETTING));

        let ok = parse_settings("{\n  // comment\n  \"claudeCode.claudeProcessWrapper\": \"/Users/mike/.cargo/bin/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\"\n}").unwrap();
        let rows = row_wrapper_setting(Some(&ok), &|_| (true, true), &sib);
        assert_eq!(rows.len(), 1);
        assert_eq!(text(&rows[0]).0, Tag::Ok);

        let js = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/x/wrapper.js\"}").unwrap();
        let rows = row_wrapper_setting(Some(&js), &|_| (true, true), &sib);
        assert!(rows.iter().any(|r| text(r).0 == Tag::Warn && text(r).1.contains("under node")));
        assert!(rows.iter().any(|r| text(r).0 == Tag::Warn && text(r).1.contains("points elsewhere")));

        let missing = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/gone\"}").unwrap();
        let rows = row_wrapper_setting(Some(&missing), &|_| (false, false), &sib);
        assert_eq!(text(&rows[0]).0, Tag::No);
        let noexec = row_wrapper_setting(Some(&missing), &|_| (true, false), &sib);
        assert!(text(&noexec[0]).1.contains("not executable"));
    }
}
