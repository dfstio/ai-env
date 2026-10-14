//! S8 part B (live, after Mike's steps in Cursor): evidence checks for T8.3
//! to T8.7, read from the census (`ai-env wrapper census --json`), the
//! session registry (`ai-env session list --json`), the lab rows (`ai-env
//! lab show PROBE --json`), the audit (the library's reader of the bridge
//! root's `audit.jsonl`: no command prints it), the Mac's mirror of a
//! session's transcript where the registry names it, and the git refs of
//! the workspace (`git for-each-ref`, `git rev-list`), never the UI. Nothing
//! here starts a VM, asks for a Touch ID or calls AWS; only T8.7's
//! `session show --settings-diff` writes (its diff, into the session's
//! quarantine).
//!
//! Each test is `#[ignore]`d and skips, saying why, unless
//! `AI_ENV_CURSOR_TESTS=1` and `AI_ENV_CURSOR_STEP` names its step (`t8_3`
//! to `t8_7`): `make test-cursor STEP=t8_3` runs `AI_ENV_CURSOR_TESTS=1
//! AI_ENV_CURSOR_STEP=t8_3 cargo test -p ai-env-cli --features bridge --test
//! cursor_live -- --ignored --nocapture`. Two optional variables narrow what
//! counts: `AI_ENV_CURSOR_SINCE`, an RFC 3339 UTC time (only rows at or
//! after it: the step's start), and `AI_ENV_CURSOR_WORKSPACE`, the workspace
//! of the chats (default: this checkout). The gated checks are never part
//! of `make test`; the readers' own offline test is.

use ai_env_cli::bridge::config::Paths;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The steps, as `AI_ENV_CURSOR_STEP` names them.
const STEPS: [&str; 5] = ["t8_3", "t8_4", "t8_5", "t8_6", "t8_7"];

/// The remote sessions' mode notes (`remote::MODE_NOTES`).
const REMOTE_MODES: [&str; 2] = ["mode:remote", "mode:remote(config)"];

/// Whether `step`'s checks run: the gate `AI_ENV_CURSOR_TESTS=1` and `AI_ENV_CURSOR_STEP` naming it; else why not, on
/// stderr. With the gate set, a step variable that is missing or names no step fails the run.
fn chosen(step: &str) -> bool {
    if std::env::var("AI_ENV_CURSOR_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set AI_ENV_CURSOR_TESTS=1 and AI_ENV_CURSOR_STEP={step} (make test-cursor STEP={step}) after the step in Cursor");
        return false;
    }
    match std::env::var("AI_ENV_CURSOR_STEP") {
        Ok(s) if s == step => true,
        Ok(s) if STEPS.contains(&s.as_str()) => {
            eprintln!("skipped: AI_ENV_CURSOR_STEP={s} checks another step");
            false
        }
        Ok(s) => panic!("AI_ENV_CURSOR_STEP={s:?} names no step: one of {STEPS:?}"),
        Err(_) => panic!("AI_ENV_CURSOR_TESTS=1 needs AI_ENV_CURSOR_STEP, one of {STEPS:?}"),
    }
}

/// `AI_ENV_CURSOR_SINCE` in Unix ms (0 when unset): rows before it do not count.
fn since_ms() -> u64 {
    match std::env::var("AI_ENV_CURSOR_SINCE") {
        Ok(t) => ai_env_cli::wire::time::parse_rfc3339_utc(t.trim()).map(|s| s * 1000).unwrap_or_else(|| panic!("AI_ENV_CURSOR_SINCE={t:?}: an RFC 3339 UTC time, such as 2026-10-14T09:00:00Z")),
        Err(_) => 0,
    }
}

/// The workspace of the chats: `AI_ENV_CURSOR_WORKSPACE`, else this checkout; canonical.
fn workspace() -> PathBuf {
    let ws = std::env::var_os("AI_ENV_CURSOR_WORKSPACE").map_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."), PathBuf::from);
    std::fs::canonicalize(&ws).unwrap_or_else(|e| panic!("the workspace {}: {e}", ws.display()))
}

/// `ai-env <args>` as the operator runs it (the lab knobs removed), bounded: its stdout, exit 0 asserted.
fn ai_env(args: &[&str]) -> String {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env"));
    cmd.args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AI_ENV_BRIDGE_LAB_") {
            cmd.env_remove(&k);
        }
    }
    let child = cmd.spawn().expect("ai-env runs");
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(out) => out.expect("ai-env output"),
        Err(_) => {
            let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            panic!("ai-env {args:?} did not finish within 60 s");
        }
    };
    let err = ai_env_cli::wire::redact::scrub(&String::from_utf8_lossy(&out.stderr)).into_owned();
    assert!(out.status.success(), "ai-env {args:?}: exit {:?}: {err}", out.status.code());
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every census row (`ai-env wrapper census --json`), oldest first.
fn census() -> Vec<Value> {
    ai_env(&["wrapper", "census", "--json"]).lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// The value of the note part `name` (`name:value`) of a census row.
fn part(row: &Value, name: &str) -> Option<String> {
    row["note"].as_str()?.rsplit("; ").find_map(|p| p.strip_prefix(name).and_then(|rest| rest.strip_prefix(':'))).map(str::to_string)
}

/// A remote session's census row (a mode note of [`REMOTE_MODES`]).
fn is_remote(row: &Value) -> bool {
    row["note"].as_str().is_some_and(|n| n.split("; ").any(|p| REMOTE_MODES.contains(&p)))
}

/// The census end rows of remote sessions that started at or after `since`, in `ws` (their cwd there or below), oldest first.
fn remote_ends(rows: &[Value], ws: &Path, since: u64) -> Vec<Value> {
    rows.iter().filter(|r| r["end"].as_u64().is_some() && r["start"].as_u64().unwrap_or(0) >= since && is_remote(r) && r["cwd"].as_str().is_some_and(|c| Path::new(c).starts_with(ws))).cloned().collect()
}

/// The `--resume` session id of a census row's argv (after the wrapper and the bundled claude).
fn resumed(row: &Value) -> Option<String> {
    let argv: Vec<String> = row["argv"].as_array()?.iter().skip(2).filter_map(|a| a.as_str().map(str::to_string)).collect();
    ai_env_cli::wire::argv::value_of(&argv, "--resume").map(str::to_string)
}

/// Every session row (`ai-env session list --json`).
fn sessions() -> Vec<Value> {
    serde_json::from_str(&ai_env(&["session", "list", "--json"])).expect("session list --json is a JSON array")
}

/// The session row the wrapper `pid` wrote (the census and the registry both name the wrapper's pid).
fn session_of(rows: &[Value], pid: u64) -> Option<Value> {
    rows.iter().find(|r| r["pid"].as_u64() == Some(pid)).cloned()
}

/// The rows of `probe` (`ai-env lab show PROBE --json`) recorded at or after `since`.
fn lab_rows(probe: &str, since: u64) -> Vec<Value> {
    let rows: Vec<Value> = serde_json::from_str(&ai_env(&["lab", "show", probe, "--json"])).expect("lab show --json is a JSON array");
    rows.into_iter().filter(|r| r["ts"].as_str().and_then(ai_env_cli::wire::time::parse_rfc3339_utc).is_some_and(|s| s * 1000 >= since)).collect()
}

/// The audit rows of `event` written at or after `since`.
fn audit(event: &str, since: u64) -> Vec<Value> {
    let paths = Paths::resolve().expect("the bridge root");
    let rows = ai_env_cli::bridge::audit::read_rows(&paths.audit(), None).expect("the audit");
    rows.into_iter().filter(|r| r["event"] == event && r["ts"].as_str().and_then(ai_env_cli::wire::time::parse_rfc3339_utc).is_some_and(|s| s * 1000 >= since)).collect()
}

/// `git args` in `ws` (read-only uses only), its stdout trimmed; exit 0 asserted.
fn git(ws: &Path, args: &[&str]) -> String {
    let o = std::process::Command::new("git").arg("-C").arg(ws).args(args).stdin(std::process::Stdio::null()).output().expect("git runs");
    assert!(o.status.success(), "git {args:?} in {}: {}", ws.display(), String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// The entries of the Mac's mirror of a session's transcript (its registry row's `mirror_root`, else
/// `~/.claude/projects`, joined with its `transcript_rel`), parsed; `Err` says why there are none (a session that
/// ran no turn, such as Cursor's config probe, has no transcript).
fn transcript(session: &Value) -> Result<Vec<Value>, String> {
    let rel = session["transcript_rel"].as_str().ok_or_else(|| format!("the session row of {} names no transcript", session["session_id"]))?;
    let root = session["mirror_root"].as_str().map_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".claude").join("projects"), PathBuf::from);
    let text = std::fs::read_to_string(root.join(rel)).map_err(|e| format!("the Mac's mirror {}: {e}", root.join(rel).display()))?;
    Ok(text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
}

/// The text of every tool result in `entries` (a `tool_result` block's string, or its text parts), one per line.
fn tool_results(entries: &[Value]) -> String {
    let mut out = String::new();
    for block in entries.iter().flat_map(|e| e["message"]["content"].as_array().cloned().unwrap_or_default()).filter(|b| b["type"] == "tool_result") {
        match &block["content"] {
            Value::String(s) => out.push_str(s),
            Value::Array(parts) => parts.iter().filter_map(|p| p["text"].as_str()).for_each(|s| out.push_str(s)),
            _ => {}
        }
        out.push('\n');
    }
    out
}

/// The tools the entries' assistant messages used, by name.
fn tools_used(entries: &[Value]) -> BTreeSet<String> {
    entries.iter().flat_map(|e| e["message"]["content"].as_array().cloned().unwrap_or_default()).filter(|b| b["type"] == "tool_use").filter_map(|b| b["name"].as_str().map(str::to_string)).collect()
}

/// What every chat's end shows: exit 0, an EOF close within the 1.5 s budget, the `initialize` pid rewritten.
fn assert_closed_well(row: &Value) {
    let what = format!("the session of wrapper pid {} ({})", row["pid"], row["ts"]);
    assert_eq!(row["exit"].as_i64(), Some(0), "{what}: its exit");
    assert_eq!(part(row, "end").as_deref(), Some("eof"), "{what}: closed by the host's EOF");
    let close_ms = part(row, "close_ms").and_then(|ms| ms.parse::<u64>().ok());
    assert!(close_ms.is_some_and(|ms| ms <= ai_env_cli::bridge::remote::CLOSE_BUDGET_MS), "{what}: close_ms {close_ms:?} (budget {} ms; tree G)", ai_env_cli::bridge::remote::CLOSE_BUDGET_MS);
    assert_eq!(part(row, "pid_rewrite").as_deref(), Some("ok"), "{what}");
}

/// T8.3 (B5): the chat in which `uname -m; id -u; pwd; cat /proc/1/comm` ran
/// (found by its transcript's tool results: aarch64, 1000, the workspace's
/// identical path, ai-env) closed well; it asked for an edit (a Write or Edit
/// tool use, after its permission prompt), was interrupted (the CLI's
/// interrupt marker in the transcript) and had its model switched (the
/// registry's model, and two models named in the transcript); every remote
/// session of the workspace since the step, the config probe's and the
/// chat's, ran on one VM, which the chat's registry row names.
#[test]
#[ignore = "live evidence after T8.3 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_3"]
fn t8_3_evidence() {
    if !chosen("t8_3") {
        return;
    }
    let (ws, since) = (workspace(), since_ms());
    let ends = remote_ends(&census(), &ws, since);
    assert!(!ends.is_empty(), "no remote session of {} in the census since AI_ENV_CURSOR_SINCE: open a chat there with the wrapper in remote mode, close it, then check", ws.display());
    let vms: BTreeSet<String> = ends.iter().filter_map(|r| part(r, "vm")).collect();
    assert_eq!(vms.len(), 1, "the config probe and the chat ran on one VM: {vms:?}");
    let sessions = sessions();
    let ws_text = ws.display().to_string();
    let chat = ends
        .iter()
        .rev()
        .filter_map(|r| session_of(&sessions, r["pid"].as_u64().unwrap_or(0)).map(|s| (r, s)))
        .find(|(_, s)| {
            let out = tool_results(&transcript(s).unwrap_or_default());
            out.lines().any(|l| l.trim() == "aarch64") && out.lines().any(|l| l.trim() == "1000") && out.lines().any(|l| l.trim() == ws_text) && out.lines().any(|l| l.trim() == "ai-env")
        });
    let Some((end, session)) = chat else {
        panic!("no remote chat of {ws_text} since AI_ENV_CURSOR_SINCE whose transcript holds the tool results aarch64, 1000, {ws_text} and ai-env (B5's first command)");
    };
    eprintln!("t8_3: the chat {} (wrapper pid {}) on {}: init_ms {}, legs {}", session["session_id"], end["pid"], part(end, "vm").unwrap_or_default(), part(end, "init_ms").unwrap_or_default(), part(end, "legs").unwrap_or_default());
    assert_closed_well(end);
    assert_eq!((session["mode"].as_str(), session["microvm_id"].as_str()), (Some("remote"), vms.iter().next().map(String::as_str)), "the chat's registry row");
    let entries = transcript(&session).unwrap_or_else(|e| panic!("{e}"));
    let tools = tools_used(&entries);
    assert!(tools.iter().any(|t| matches!(t.as_str(), "Write" | "Edit" | "MultiEdit")), "the edit asked for (after its permission prompt): the tools used {tools:?}");
    let text: Vec<String> = entries.iter().map(Value::to_string).collect();
    assert!(text.iter().any(|t| t.contains("Request interrupted by user")), "the interrupt: no interrupt marker in the transcript");
    assert!(session["host_state"]["model"].as_str().is_some_and(|m| !m.is_empty()), "the model switch: the registry's model is unset");
    let models: BTreeSet<&str> = entries.iter().filter(|e| e["type"] == "assistant").filter_map(|e| e["message"]["model"].as_str()).collect();
    assert!(models.len() >= 2, "the model switch: the transcript's answers name {models:?}");
}

/// T8.4 (B6): a chat reopened from the picker (`--resume`) ran on the VM it
/// had (reused or resumed) with its transcript already there, under the same
/// session id (its registry row names that VM), and closed well; the VM's
/// commit came into `refs/remotes/box/<branch>` (a commit the Mac's branch
/// lacks) and its uncommitted edit into a `box/wip/*` ref that differs from
/// it. The transcripts' hashes (VM against Mac) are compared by hand.
#[test]
#[ignore = "live evidence after T8.4 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_4"]
fn t8_4_evidence() {
    if !chosen("t8_4") {
        return;
    }
    let (ws, since) = (workspace(), since_ms());
    let sessions = sessions();
    let reopened = remote_ends(&census(), &ws, since).into_iter().rev().find(|r| {
        resumed(r).is_some() && matches!(part(r, "vm_how").as_deref(), Some("reused" | "resumed")) && matches!(part(r, "transcript").as_deref(), Some("already_there" | "vm_longer"))
    });
    let Some(end) = reopened else {
        panic!("no chat of {} reopened from the picker onto its VM since AI_ENV_CURSOR_SINCE (a remote end row with --resume, vm_how reused or resumed, transcript already_there)", ws.display());
    };
    let id = resumed(&end).unwrap_or_default();
    eprintln!("t8_4: {id} reopened on {} ({}), init_ms {}", part(&end, "vm").unwrap_or_default(), part(&end, "vm_how").unwrap_or_default(), part(&end, "init_ms").unwrap_or_default());
    assert_closed_well(&end);
    let row = sessions.iter().find(|s| s["session_id"] == id.as_str()).unwrap_or_else(|| panic!("no registry row of {id}"));
    assert_eq!(row["microvm_id"].as_str(), part(&end, "vm").as_deref(), "the same session id on the same VM");
    let branch = git(&ws, &["branch", "--show-current"]);
    assert!(!branch.is_empty(), "the workspace is on a branch");
    let boxed = format!("refs/remotes/box/{branch}");
    let ahead: u64 = git(&ws, &["rev-list", "--count", &format!("{branch}..{boxed}")]).parse().unwrap_or(0);
    assert!(ahead >= 1, "the VM's commit: {boxed} holds no commit {branch} lacks (git log {branch}..box/{branch})");
    let wips = git(&ws, &["for-each-ref", "--sort=-refname", "--format=%(refname)", "refs/remotes/box/wip/"]);
    let newest = wips.lines().next().unwrap_or_else(|| panic!("the uncommitted edit: no refs/remotes/box/wip/* ref"));
    assert_ne!(git(&ws, &["rev-parse", &format!("{newest}^{{tree}}")]), git(&ws, &["rev-parse", &format!("{boxed}^{{tree}}")]), "the newest box/wip ref {newest} holds no edit beyond {boxed}");
}

/// T8.5 (B7): a chat reopened from the picker after its VM was terminated
/// ran on a new VM (started) with its transcript put there first (the dup
/// probes' census evidence: `transcript:uploaded`, or the resume miss's
/// retry), the upload audited; and both dup probes were recorded
/// no-duplicate since the step.
#[test]
#[ignore = "live evidence after T8.5 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_5"]
fn t8_5_evidence() {
    if !chosen("t8_5") {
        return;
    }
    let (ws, since) = (workspace(), since_ms());
    let rows: Vec<Value> = census().into_iter().filter(|r| r["start"].as_u64().unwrap_or(0) >= since && r["cwd"].as_str().is_some_and(|c| Path::new(c).starts_with(&ws))).collect();
    let evidence = ai_env_cli::bridge::probes::resume_evidence(&rows).unwrap_or_else(|why| panic!("T8.5's resume: {why}"));
    eprintln!("t8_5: {evidence}");
    assert!(evidence.contains("(vm_how:started)"), "a new VM after the terminate: {evidence}");
    assert!(!audit("transcript_put", since).is_empty(), "no transcript_put audit row since AI_ENV_CURSOR_SINCE");
    for probe in ["dup-init", "dup-user-replay"] {
        let newest = lab_rows(probe, since).pop().unwrap_or_else(|| panic!("{probe}: nothing recorded since AI_ENV_CURSOR_SINCE (ai-env lab run {probe} --manual VERDICT)"));
        assert_eq!(newest["verdict"].as_str(), Some("no-duplicate"), "{probe}: {newest}");
    }
}

/// T8.6 (B8): (a) a chat whose transport was dropped (`session drop-transport`)
/// lost and regained its link (`link_drops` of 1 or more, `agent_reconnect`
/// audited) and still closed well; (c) a chat in a workspace whose path holds
/// a non-ASCII character ran at its NFC form, its registry slug the NFC
/// path's. (b), (d), (e) and (f) are checked by hand.
#[test]
#[ignore = "live evidence after T8.6 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_6"]
fn t8_6_evidence() {
    if !chosen("t8_6") {
        return;
    }
    let (ws, since) = (workspace(), since_ms());
    let census = census();
    let dropped = remote_ends(&census, &ws, since).into_iter().rev().find(|r| part(r, "link_drops").and_then(|n| n.parse::<u64>().ok()).is_some_and(|n| n >= 1));
    let Some(dropped) = dropped else {
        panic!("(a): no remote session of {} since AI_ENV_CURSOR_SINCE with link_drops 1 or more (ai-env session drop-transport UUID during a turn)", ws.display());
    };
    eprintln!("t8_6 (a): wrapper pid {} on {}: link_drops {}", dropped["pid"], part(&dropped, "vm").unwrap_or_default(), part(&dropped, "link_drops").unwrap_or_default());
    assert_closed_well(&dropped);
    assert!(!audit("agent_reconnect", since).is_empty(), "(a): no agent_reconnect audit row since AI_ENV_CURSOR_SINCE");
    let sessions = sessions();
    // The chat's end row, never a config probe's or a suggestion query's: those end without a
    // registry row (no user line, or --no-session-persistence), and the probe's often ends first.
    let wide = census
        .iter()
        .filter(|r| r["end"].as_u64().is_some() && r["start"].as_u64().unwrap_or(0) >= since && is_remote(r) && r["cwd"].as_str().is_some_and(|c| !c.is_ascii()))
        .find_map(|r| session_of(&sessions, r["pid"].as_u64().unwrap_or(0)).map(|row| (r, row)));
    let Some((wide, row)) = wide else {
        panic!("(c): no remote chat with a registry row since AI_ENV_CURSOR_SINCE in a workspace whose path holds a non-ASCII character (the Cyrillic fixture)");
    };
    // The Mac's path is in whatever form its directory was made (APFS keeps it); the VM's and the slug are the NFC form's.
    let cwd = wide["cwd"].as_str().unwrap_or_default();
    let nfc = ai_env_cli::wire::workspace::nfc(cwd);
    let slug = ai_env_cli::wire::slug::slug_of(&nfc);
    assert_eq!(row["slug"].as_str(), Some(slug.as_str()), "(c): one slug, the NFC path's (the Mac's path {} NFC)", if nfc == cwd { "is" } else { "is not" });
    eprintln!("t8_6 (c): {nfc} as {slug}; (b), (d), (e), (f): by hand");
}

/// T8.7 (B9): settings persistence: the newest fresh-claude-json row since
/// the step is no-stall; `wrapper settings-sync --write` was audited; a
/// remote chat of the workspace since the step had its settings captured
/// into its quarantine, and `session show --settings-diff` writes its diff
/// there.
#[test]
#[ignore = "live evidence after T8.7 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_7"]
fn t8_7_evidence() {
    use ai_env_cli::bridge::settings_capture::{capture_path, CapturePhase, DIFF_FILE};
    if !chosen("t8_7") {
        return;
    }
    let (ws, since) = (workspace(), since_ms());
    let fresh = lab_rows("fresh-claude-json", since).pop().unwrap_or_else(|| panic!("fresh-claude-json: nothing recorded since AI_ENV_CURSOR_SINCE (ai-env lab run fresh-claude-json)"));
    assert_eq!(fresh["verdict"].as_str(), Some("no-stall"), "fresh-claude-json: {fresh}");
    assert!(!audit("settings_sync", since).is_empty(), "no settings_sync audit row since AI_ENV_CURSOR_SINCE (ai-env wrapper settings-sync UUID --write)");
    let paths = Paths::resolve().expect("the bridge root");
    let sessions = sessions();
    let captured = remote_ends(&census(), &ws, since).into_iter().rev().filter_map(|r| session_of(&sessions, r["pid"].as_u64().unwrap_or(0))).find(|s| {
        let id = s["session_id"].as_str().unwrap_or_default();
        [CapturePhase::Start, CapturePhase::Turn].iter().any(|phase| capture_path(&paths, id, *phase).is_ok_and(|p| p.is_file()))
    });
    let Some(session) = captured else {
        panic!("no remote chat of {} since AI_ENV_CURSOR_SINCE with a settings capture in its quarantine", ws.display());
    };
    let id = session["session_id"].as_str().unwrap_or_default().to_string();
    let t = Instant::now();
    ai_env(&["session", "show", &id, "--settings-diff", "--json"]);
    let diff = paths.quarantine_session(&id).join("settings").join(DIFF_FILE);
    assert!(diff.is_file(), "session show --settings-diff wrote no {}", diff.display());
    eprintln!("t8_7: {id}: the capture and its diff ({} ms); fresh-claude-json {}", t.elapsed().as_millis(), fresh["note"].as_str().unwrap_or_default().chars().take(200).collect::<String>());
}

/// Offline (no gate, nothing live): the readers the checks rest on take the
/// census's and the transcript's shapes: note parts by name (`vm` is not
/// `vm_how`), remote end rows of the workspace since a time, a `--resume`
/// in either spelling, the tool results (a string or text parts) and the
/// tools used.
#[test]
fn the_evidence_readers_take_the_census_and_transcript_shapes() {
    let ws = Path::new("/Users/mike/Documents/DeFi/ai-env");
    let row = |pid: u64, start: u64, cwd: &str, mode: &str, end: bool, args: &[&str]| {
        let argv: Vec<&str> = ["/x/ai-env-claude", "/x/claude"].iter().copied().chain(args.iter().copied()).collect();
        let mut r = serde_json::json!({"pid": pid, "start": start, "cwd": cwd, "argv": argv, "note": format!("{mode}; end:eof; vm:microvm-a; vm_how:reused; close_ms:600")});
        if end {
            r["end"] = serde_json::json!(start + 5);
        }
        r
    };
    let rows = vec![
        row(1, 100, "/Users/mike/Documents/DeFi/ai-env", "mode:remote", true, &[]),
        row(2, 50, "/Users/mike/Documents/DeFi/ai-env", "mode:remote", true, &[]),
        row(3, 200, "/Users/mike/Documents/DeFi/ai-env/target/s8/x", "mode:remote(config)", true, &["--resume", "a1"]),
        row(4, 300, "/Users/mike/Documents/DeFi/other", "mode:remote", true, &[]),
        row(5, 400, "/Users/mike/Documents/DeFi/ai-env", "mode:local-child", true, &[]),
        row(6, 500, "/Users/mike/Documents/DeFi/ai-env", "mode:remote", false, &["--resume=b2"]),
    ];
    let ends = remote_ends(&rows, ws, 60);
    assert_eq!(ends.iter().map(|r| r["pid"].as_u64().unwrap()).collect::<Vec<_>>(), [1, 3], "remote, ended, since 60, in the workspace");
    assert_eq!((part(&ends[0], "vm").as_deref(), part(&ends[0], "vm_how").as_deref(), part(&ends[0], "close_ms").as_deref()), (Some("microvm-a"), Some("reused"), Some("600")));
    assert_eq!((resumed(&ends[1]).as_deref(), resumed(&rows[5]).as_deref(), resumed(&ends[0])), (Some("a1"), Some("b2"), None));
    let entries: Vec<Value> = [
        r#"{"type":"assistant","message":{"model":"m1","content":[{"type":"tool_use","name":"Bash","input":{}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","content":"aarch64\n1000"}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","content":[{"type":"text","text":"/Users/mike/Documents/DeFi/ai-env"}]}]}}"#,
        r#"{"type":"assistant","message":{"model":"m2","content":[{"type":"tool_use","name":"Edit","input":{}},{"type":"text","text":"done"}]}}"#,
    ]
    .iter()
    .map(|l| serde_json::from_str(l).unwrap())
    .collect();
    assert_eq!(tool_results(&entries), "aarch64\n1000\n/Users/mike/Documents/DeFi/ai-env\n");
    assert_eq!(tools_used(&entries).into_iter().collect::<Vec<_>>(), ["Bash", "Edit"]);
    assert_eq!(session_of(&[serde_json::json!({"pid": 7, "session_id": "s"})], 7).map(|s| s["session_id"].clone()), Some(serde_json::json!("s")));
}
