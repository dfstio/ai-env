//! S8 part B (live, after Mike's steps in Cursor): evidence checks for T8.3
//! to T8.7, read from the census (`ai-env wrapper census --json`), the
//! session registry (`ai-env session list --json`), the lab rows (`ai-env
//! lab show PROBE --json`), the audit (the library's reader of the bridge
//! root's `audit.jsonl`: no command prints it), a remote chat's view on the
//! Mac where the registry names it (S9: its transcript is kept in S3, the
//! Mac holds its last messages only), and the git refs of
//! the workspace (`git for-each-ref`, `git rev-list`), never the UI. Nothing
//! here starts a VM, asks for a Touch ID or calls AWS; only T8.7's
//! `session show --settings-diff` writes (its diff, into the session's
//! quarantine).
//!
//! Each test is `#[ignore]`d and skips, saying why, unless
//! `AI_ENV_CURSOR_TESTS=1` and `AI_ENV_CURSOR_STEP` names its step (`t8_3`
//! to `t8_7`): `make test-cursor STEP=t8_3 SINCE=…` runs
//! `AI_ENV_CURSOR_TESTS=1 AI_ENV_CURSOR_STEP=t8_3 AI_ENV_CURSOR_SINCE=…
//! cargo test -p ai-env-cli --features bridge --test cursor_live --
//! --ignored --nocapture`. `AI_ENV_CURSOR_SINCE` is required (S9, L10): an
//! RFC 3339 UTC time no later than now (only rows at or after it: the
//! step's start, so evidence of an earlier step never passes for this one),
//! or `all` to read every row. `AI_ENV_CURSOR_WORKSPACE`, optional, is the
//! workspace of the chats (default: this checkout). The gated checks are
//! never part of `make test`; the readers' own offline tests are.

use ai_env_cli::bridge::config::Paths;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The steps, as `AI_ENV_CURSOR_STEP` names them (S9: `t9_s3`, the S3 store's chats).
const STEPS: [&str; 6] = ["t8_3", "t8_4", "t8_5", "t8_6", "t8_7", "t9_s3"];

/// The remote sessions' mode notes (`remote::MODE_NOTES`).
const REMOTE_MODES: [&str; 2] = ["mode:remote", "mode:remote(config)"];

/// Whether `step`'s checks run: the gate `AI_ENV_CURSOR_TESTS=1` and `AI_ENV_CURSOR_STEP` naming it; else why not, on
/// stderr. With the gate set, a step variable that is missing or names no step fails the run.
fn chosen(step: &str) -> bool {
    if std::env::var("AI_ENV_CURSOR_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set AI_ENV_CURSOR_TESTS=1, AI_ENV_CURSOR_STEP={step} and AI_ENV_CURSOR_SINCE (make test-cursor STEP={step} SINCE=…) after the step in Cursor");
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

/// `AI_ENV_CURSOR_SINCE` ([`since_from`]) in Unix ms: rows before it do not
/// count; a value it refuses fails the run.
fn since_of() -> u64 {
    let value = std::env::var_os("AI_ENV_CURSOR_SINCE").map(|v| v.to_string_lossy().into_owned());
    since_from(value.as_deref(), ai_env_cli::wire::time::unix_now()).unwrap_or_else(|why| panic!("{why}"))
}

/// `AI_ENV_CURSOR_SINCE`'s value (`None`: unset) in Unix ms, at `now` (Unix
/// seconds): an RFC 3339 UTC time no later than `now`, or `all` (0, every
/// row). Unset or empty is refused (make test-cursor asks for it before
/// cargo), and so is a time in the future: a typo there would pass every
/// check on no evidence at all.
fn since_from(value: Option<&str>, now: u64) -> Result<u64, String> {
    let hint = "take the step's start (date -u +%Y-%m-%dT%H:%M:%SZ) before the step in Cursor, or pass all to read every row";
    match value.map(str::trim) {
        None | Some("") => Err(format!("AI_ENV_CURSOR_SINCE is missing: {hint}")),
        Some("all") => Ok(0),
        Some(t) => match ai_env_cli::wire::time::parse_rfc3339_utc(t) {
            Some(s) if s > now => Err(format!("AI_ENV_CURSOR_SINCE={t:?} is in the future (now {}): {hint}", ai_env_cli::wire::time::rfc3339_utc(now))),
            Some(s) => Ok(s * 1000),
            None => Err(format!("AI_ENV_CURSOR_SINCE={t:?}: an RFC 3339 UTC time, such as 2026-10-14T09:00:00Z, or all")),
        },
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

/// The text blocks of a remote chat's view on the Mac (S9: its registry row's `view`, else its `transcript_rel`,
/// under its `mirror_root`, else `~/.claude/projects`), in order: each view line's `message.content[].text`. `Err`
/// says why there are none (a session that ran no turn, such as Cursor's config probe, has no view). The view
/// holds the last messages only: a user's prompts and an assistant's text, its tool calls as `[tool: NAME]` blocks;
/// never a tool's result, a model's name or a thinking block, which only the transcript in S3 holds.
fn view_texts(session: &Value) -> Result<Vec<String>, String> {
    let rel = session["view"].as_str().or_else(|| session["transcript_rel"].as_str()).ok_or_else(|| format!("the session row of {} names no view", session["session_id"]))?;
    let root = session["mirror_root"].as_str().map_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".claude").join("projects"), PathBuf::from);
    let text = std::fs::read_to_string(root.join(rel)).map_err(|e| format!("the Mac's view {}: {e}", root.join(rel).display()))?;
    let lines: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    Ok(lines.iter().flat_map(|l| l["message"]["content"].as_array().cloned().unwrap_or_default()).filter_map(|b| b["text"].as_str().map(str::to_string)).collect())
}

/// The tools a view shows called (its `[tool: NAME]` blocks, `wire::view::tool_text`), by name.
fn tools_shown(texts: &[String]) -> BTreeSet<String> {
    texts.iter().filter_map(|t| t.strip_prefix("[tool: ")?.strip_suffix(']').map(str::to_string)).collect()
}

/// Whether a view shows the CLI's interrupt marker (a user's `[Request interrupted by user…]` text).
fn interrupted(texts: &[String]) -> bool {
    texts.iter().any(|t| t.contains("Request interrupted by user"))
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

/// T8.3 (B5): the chat in which `uname -m; id -u; pwd; cat /proc/1/comm` ran,
/// asked for an edit and was interrupted, found by what its view on the Mac
/// shows (S9: the transcript is kept in S3; the view holds its last
/// messages): a `[tool: Bash]` block (B5's first command), a Write or Edit
/// block (the edit, after its permission prompt) and the CLI's interrupt
/// marker. It closed well, and had its model switched (the registry's
/// model); every remote session of the workspace since the step, the config
/// probe's and the chat's, ran on one VM, which the chat's registry row
/// names. What only the transcript holds (the tool results, the models
/// named) is checked by hand in Cursor.
#[test]
#[ignore = "live evidence after T8.3 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_3 SINCE=…"]
fn t8_3_evidence() {
    if !chosen("t8_3") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
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
            let texts = view_texts(s).unwrap_or_default();
            let tools = tools_shown(&texts);
            tools.contains("Bash") && tools.iter().any(|t| matches!(t.as_str(), "Write" | "Edit" | "MultiEdit")) && interrupted(&texts)
        });
    let Some((end, session)) = chat else {
        panic!("no remote chat of {ws_text} since AI_ENV_CURSOR_SINCE whose view shows a [tool: Bash] block (B5's first command), a Write or Edit block (the edit) and the interrupt marker");
    };
    eprintln!("t8_3: the chat {} (wrapper pid {}) on {}: init_ms {}, legs {}", session["session_id"], end["pid"], part(end, "vm").unwrap_or_default(), part(end, "init_ms").unwrap_or_default(), part(end, "legs").unwrap_or_default());
    assert_closed_well(end);
    assert_eq!((session["mode"].as_str(), session["microvm_id"].as_str()), (Some("remote"), vms.iter().next().map(String::as_str)), "the chat's registry row");
    assert_eq!(session["transcript_home"].as_str(), Some("s3"), "the chat's transcript is kept in S3");
    assert!(session["host_state"]["model"].as_str().is_some_and(|m| !m.is_empty()), "the model switch: the registry's model is unset");
}

/// T8.4 (B6): a chat reopened from the picker (`--resume`) ran on the VM it
/// had (reused or resumed) with its transcript already there (S9's `kept`:
/// the VM held the committed prefix; S8's `already_there` or `vm_longer`), under the same
/// session id (its registry row names that VM), and closed well; the VM's
/// commit came into `refs/remotes/box/<branch>` (a commit the Mac's branch
/// lacks) and its uncommitted edit into a `box/wip/*` ref that differs from
/// it. The transcripts' hashes (VM against Mac) are compared by hand.
#[test]
#[ignore = "live evidence after T8.4 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_4 SINCE=…"]
fn t8_4_evidence() {
    if !chosen("t8_4") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let sessions = sessions();
    let reopened = remote_ends(&census(), &ws, since).into_iter().rev().find(|r| {
        resumed(r).is_some() && matches!(part(r, "vm_how").as_deref(), Some("reused" | "resumed")) && matches!(part(r, "transcript").as_deref(), Some("kept" | "already_there" | "vm_longer"))
    });
    let Some(end) = reopened else {
        panic!("no chat of {} reopened from the picker onto its VM since AI_ENV_CURSOR_SINCE (a remote end row with --resume, vm_how reused or resumed, transcript kept)", ws.display());
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
/// probes' census evidence: S9's `transcript:restored`, `transcript:staged`
/// for a chat S3 did not hold yet, or the resume miss's retry), its pull
/// from S3 audited (`transcript_pull`, `written`); and both
/// dup probes were recorded no-duplicate since the step.
#[test]
#[ignore = "live evidence after T8.5 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_5 SINCE=…"]
fn t8_5_evidence() {
    if !chosen("t8_5") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let rows: Vec<Value> = census().into_iter().filter(|r| r["start"].as_u64().unwrap_or(0) >= since && r["cwd"].as_str().is_some_and(|c| Path::new(c).starts_with(&ws))).collect();
    let evidence = ai_env_cli::bridge::probes::resume_evidence(&rows).unwrap_or_else(|why| panic!("T8.5's resume: {why}"));
    eprintln!("t8_5: {evidence}");
    assert!(evidence.contains("(vm_how:started)"), "a new VM after the terminate: {evidence}");
    assert!(audit("transcript_pull", since).iter().any(|r| r["detail"]["outcome"] == "written"), "no transcript_pull audit row with outcome written since AI_ENV_CURSOR_SINCE");
    for probe in ["dup-init", "dup-user-replay"] {
        let newest = lab_rows(probe, since).pop().unwrap_or_else(|| panic!("{probe}: nothing recorded since AI_ENV_CURSOR_SINCE (ai-env lab run {probe} --manual VERDICT)"));
        assert_eq!(newest["verdict"].as_str(), Some("no-duplicate"), "{probe}: {newest}");
    }
}

/// T8.6 (a)'s chain (S9, L10), pure: the newest `drop_transport` audit row
/// (`drops`) at or after `since` (Unix ms) names the session's wrapper
/// (`wrapper_pid`) and when the drop went out; that wrapper's census end row
/// (`census`) whose run holds the drop shows `link_drops` of 1 or more; the
/// `agent_reconnect` rows (`reconnects`) that wrapper wrote (their `pid`)
/// carry the end row's `spawn` and come at or after the drop. `Ok`: that end
/// row (for [`assert_closed_well`]) and the evidence in one line; `Err`:
/// what is missing.
fn reconnect_evidence(census: &[Value], drops: &[Value], reconnects: &[Value], since: u64) -> Result<(Value, String), String> {
    let secs = |r: &Value| r["ts"].as_str().and_then(ai_env_cli::wire::time::parse_rfc3339_utc);
    let drop = drops
        .iter()
        .filter(|r| r["event"] == "drop_transport" && secs(r).is_some_and(|s| s * 1000 >= since))
        .max_by_key(|r| secs(r))
        .ok_or("no drop_transport audit row since AI_ENV_CURSOR_SINCE (ai-env session drop-transport UUID during a turn)")?;
    let pid: u64 = drop["detail"]["wrapper_pid"].as_str().and_then(|p| p.parse().ok()).ok_or_else(|| format!("the drop_transport row names no wrapper pid: {drop}"))?;
    let at = secs(drop).unwrap_or_default() * 1000;
    // The drop's time is its row's second: the run holds it when it started by that second's end and ended after its start.
    let end = census
        .iter()
        .filter(|r| r["pid"].as_u64() == Some(pid) && r["start"].as_u64().is_some_and(|s| s < at + 1000) && r["end"].as_u64().is_some_and(|e| e >= at))
        .max_by_key(|r| r["start"].as_u64())
        .ok_or_else(|| format!("no census end row of wrapper pid {pid} whose run holds the drop at {}", drop["ts"]))?;
    let link_drops = part(end, "link_drops").and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
    if link_drops < 1 {
        return Err(format!("the end row of wrapper pid {pid} shows link_drops {link_drops}: the drop at {} lost no link", drop["ts"]));
    }
    let spawn = part(end, "spawn").ok_or_else(|| format!("the end row of wrapper pid {pid} names no spawn"))?;
    let theirs: Vec<&Value> = reconnects.iter().filter(|r| r["event"] == "agent_reconnect" && r["pid"].as_u64() == Some(pid)).collect();
    if theirs.is_empty() {
        return Err(format!("no agent_reconnect audit row of wrapper pid {pid}"));
    }
    let after = theirs.iter().filter(|r| r["detail"]["spawn"].as_str() == Some(spawn.as_str()) && secs(r).is_some_and(|s| s * 1000 >= at)).count();
    if after == 0 {
        return Err(format!("no agent_reconnect row of wrapper pid {pid} carries spawn {spawn} at or after the drop at {} (its rows: {})", drop["ts"], theirs.iter().map(|r| format!("{} {}", r["ts"], r["detail"]["spawn"])).collect::<Vec<_>>().join(", ")));
    }
    let session = drop["detail"]["session"].as_str().unwrap_or("?");
    Ok((end.clone(), format!("session {session}: wrapper pid {pid}, spawn {spawn}, dropped at {}, link_drops {link_drops}, {after} reconnect(s) at or after it", drop["ts"])))
}

/// T8.6 (B8): (a) a chat whose transport was dropped (`session drop-transport`)
/// lost and regained its link and still closed well, its evidence chained to
/// that drop (S9, [`reconnect_evidence`]: the `drop_transport` row's wrapper,
/// its end row's `link_drops` and spawn, its own `agent_reconnect` rows
/// after the drop); (c) a chat in a workspace whose path holds a non-ASCII
/// character ran at its NFC form, its registry slug the NFC path's. (b),
/// (d), (e) and (f) are checked by hand.
#[test]
#[ignore = "live evidence after T8.6 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_6 SINCE=…"]
fn t8_6_evidence() {
    if !chosen("t8_6") {
        return;
    }
    let since = since_of();
    let census = census();
    let (dropped, evidence) = reconnect_evidence(&census, &audit("drop_transport", since), &audit("agent_reconnect", since), since).unwrap_or_else(|why| panic!("(a): {why}"));
    eprintln!("t8_6 (a): {evidence} (on {})", part(&dropped, "vm").unwrap_or_default());
    assert_closed_well(&dropped);
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
#[ignore = "live evidence after T8.7 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t8_7 SINCE=…"]
fn t8_7_evidence() {
    use ai_env_cli::bridge::settings_capture::{capture_path, CapturePhase, DIFF_FILE};
    if !chosen("t8_7") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
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

/// The Mac's projects directory (`$CLAUDE_CONFIG_DIR/projects`, else `~/.claude/projects`): where a remote chat's view is.
fn mac_projects() -> PathBuf {
    std::env::var_os("CLAUDE_CONFIG_DIR").map_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".claude"), PathBuf::from).join("projects")
}

/// The messages of a view's lines: its prompts and replies (the title and the custom titles are no messages).
fn view_messages(text: &str) -> usize {
    text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v["type"] == "user" || v["type"] == "assistant").count()
}

/// The audit rows of `event` since `since` whose detail names `session`.
fn audit_of(event: &str, since: u64, session: &str) -> Vec<Value> {
    audit(event, since).into_iter().filter(|r| r["detail"]["session"] == session).collect()
}

/// S9 B6 (`make test-cursor STEP=t9_s3`; S9 wave 2: G8): the S3 store's
/// chats in Cursor, after S9's cut-over. Since the step's start, in the
/// workspace: a remote chat whose transcript is kept in S3 (its registry
/// row: `transcript_home` s3, begun in the VM, its view's rel), whose turns
/// went up (`transcript_push` audited with S3's 200) while the Mac holds only
/// its view (the view's mark first, at most `[transcript].view_messages`
/// messages, `transcript_view` written); that chat reopened from the picker
/// on its VM (`transcript:kept`) and into a new VM, restored from S3
/// (`transcript:restored`, `transcript_pull` written), each closing well;
/// and a local resume of that chat's view refused (a census row in the
/// workspace noting `view_refused:resume` with its id in the argv, or
/// `view_refused:continue`). Whether the answers kept the chat's context is
/// judged in Cursor, by hand.
#[test]
#[ignore = "live evidence after S9's S3 step in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t9_s3 SINCE=…"]
fn t9_s3_evidence() {
    if !chosen("t9_s3") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let rows = census();
    let ends = remote_ends(&rows, &ws, since);
    let sessions = sessions();
    let chat = ends.iter().rev().filter_map(|r| session_of(&sessions, r["pid"].as_u64().unwrap_or(0))).find(|s| s["transcript_home"] == "s3" && s["origin"] == "vm" && s["view"].is_string());
    let Some(chat) = chat else {
        panic!("no remote chat of {} since AI_ENV_CURSOR_SINCE whose transcript is kept in S3 (a session row with transcript_home s3, origin vm and a view): open one with the wrapper in remote mode and run a turn", ws.display());
    };
    let id = chat["session_id"].as_str().unwrap_or_default().to_string();
    let view = mac_projects().join(chat["view"].as_str().unwrap_or_default());
    let text = std::fs::read_to_string(&view).unwrap_or_else(|e| panic!("{id}'s view {}: {e}", view.display()));
    let head = &text.as_bytes()[..text.len().min(ai_env_cli::wire::view::VIEW_HEAD_READ)];
    assert!(ai_env_cli::wire::view::is_view_head(head), "{id}: {} is not a view: the Mac holds more than the view", view.display());
    let max = ai_env_cli::bridge::config::BridgeConfig::load(&Paths::resolve().expect("the bridge root")).ok().flatten().map_or(ai_env_cli::wire::view::VIEW_MESSAGES_DEFAULT, |c| c.transcript.view_messages);
    let messages = view_messages(&text);
    assert!(messages >= 1 && messages <= max as usize, "{id}: the view holds {messages} messages (at most {max})");
    let pushes = audit_of("transcript_push", since, &id);
    assert!(!pushes.is_empty() && pushes.iter().all(|r| r["detail"]["s3_status"] == "200"), "{id}: its turns went up to S3 (transcript_push, S3's 200): {pushes:?}");
    assert!(audit_of("transcript_view", since, &id).iter().any(|r| r["detail"]["outcome"] == "written"), "{id}: its view was written (transcript_view)");
    let reopened: Vec<&Value> = ends.iter().filter(|r| resumed(r).as_deref() == Some(id.as_str())).collect();
    let kept = reopened.iter().find(|r| part(r, "transcript").as_deref() == Some("kept") && matches!(part(r, "vm_how").as_deref(), Some("reused" | "resumed")));
    let restored = reopened.iter().find(|r| part(r, "transcript").as_deref() == Some("restored") && part(r, "vm_how").as_deref() == Some("started"));
    let (Some(kept), Some(restored)) = (kept, restored) else {
        panic!("{id}: reopened from the picker on its VM (transcript:kept) and into a new VM (transcript:restored, vm_how started) since AI_ENV_CURSOR_SINCE: found {:?}", reopened.iter().map(|r| (part(r, "vm_how"), part(r, "transcript"))).collect::<Vec<_>>());
    };
    for end in [kept, restored] {
        assert_closed_well(end);
    }
    assert!(audit_of("transcript_pull", since, &id).iter().any(|r| r["detail"]["outcome"] == "written"), "{id}: the restore into the new VM (transcript_pull written)");
    // This chat's view: a `--resume` of its id, or a `--continue` in the workspace (it names no id).
    let refused: Vec<&Value> = rows
        .iter()
        .filter(|r| r["start"].as_u64().unwrap_or(0) >= since && r["cwd"].as_str().is_some_and(|c| Path::new(c).starts_with(&ws)))
        .filter(|r| r["note"].as_str().is_some_and(|n| n.split("; ").any(|p| (p == "view_refused:resume" && resumed(r).as_deref() == Some(id.as_str())) || p == "view_refused:continue")))
        .collect();
    assert!(!refused.is_empty(), "{id}: no local resume of its view refused in {} since AI_ENV_CURSOR_SINCE (a census row noting view_refused:resume with its id, or view_refused:continue): reopen the chat with the wrapper in passthrough", ws.display());
    eprintln!("t9_s3: {id}: {} pushes; the view {messages} messages; reopened kept on {} and restored on {}; {} local resume(s) refused", pushes.len(), part(kept, "vm").unwrap_or_default(), part(restored, "vm").unwrap_or_default(), refused.len());
}

/// Offline (no gate, nothing live): the readers the checks rest on take the
/// census's and the view's shapes: note parts by name (`vm` is not
/// `vm_how`), remote end rows of the workspace since a time, a `--resume`
/// in either spelling, a view's text blocks (from its registry row's
/// `view`), the tools it shows called and the interrupt marker.
#[test]
fn the_evidence_readers_take_the_census_and_view_shapes() {
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
    let dir = tempfile::tempdir().unwrap();
    let rel = "-Users-mike-Documents-DeFi-ai-env/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl";
    let lines = [
        r#"{"aiEnvView":1,"type":"ai-title","aiTitle":"Run the checks","sessionId":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"}"#,
        r#"{"aiEnvView":1,"parentUuid":null,"type":"user","message":{"role":"user","content":[{"type":"text","text":"run uname -m; id -u; pwd"}]},"uuid":"u1"}"#,
        r#"{"aiEnvView":1,"parentUuid":"u1","type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"[tool: Bash]"},{"type":"text","text":"aarch64, 1000"},{"type":"text","text":"[tool: Edit]"}]},"uuid":"a1"}"#,
        r#"{"aiEnvView":1,"parentUuid":"a1","type":"user","message":{"role":"user","content":[{"type":"text","text":"[Request interrupted by user for tool use]"}]},"uuid":"u2"}"#,
    ];
    std::fs::create_dir_all(dir.path().join(rel).parent().unwrap()).unwrap();
    std::fs::write(dir.path().join(rel), lines.join("\n") + "\n").unwrap();
    let session = serde_json::json!({"session_id": "s", "view": rel, "mirror_root": dir.path().display().to_string()});
    let texts = view_texts(&session).unwrap();
    assert_eq!(texts, ["run uname -m; id -u; pwd", "[tool: Bash]", "aarch64, 1000", "[tool: Edit]", "[Request interrupted by user for tool use]"]);
    assert_eq!(tools_shown(&texts).into_iter().collect::<Vec<_>>(), ["Bash", "Edit"]);
    assert!(interrupted(&texts) && !interrupted(&texts[..3]));
    assert!(view_texts(&serde_json::json!({"session_id": "s"})).unwrap_err().contains("names no view"));
    assert_eq!(session_of(&[serde_json::json!({"pid": 7, "session_id": "s"})], 7).map(|s| s["session_id"].clone()), Some(serde_json::json!("s")));
}

/// S9 (L10): `AI_ENV_CURSOR_SINCE` is required: an RFC 3339 UTC time no
/// later than now (in Unix ms), or `all` (every row); unset, empty, a time
/// in the future or anything else is refused, naming how to take the step's
/// start.
#[test]
fn since_takes_a_time_or_all_and_refuses_empty() {
    let now = ai_env_cli::wire::time::parse_rfc3339_utc("2026-10-18T12:00:00Z").unwrap();
    assert_eq!(since_from(Some("2026-10-14T09:00:00Z"), now), Ok(ai_env_cli::wire::time::parse_rfc3339_utc("2026-10-14T09:00:00Z").unwrap() * 1000));
    assert_eq!(since_from(Some(" 2026-10-18T12:00:00Z\n"), now), Ok(now * 1000), "now itself, the blanks around it trimmed");
    assert_eq!(since_from(Some("all"), now), Ok(0), "every row");
    for missing in [None, Some(""), Some("  ")] {
        let why = since_from(missing, now).unwrap_err();
        assert!(why.starts_with("AI_ENV_CURSOR_SINCE is missing: take the step's start (date -u +%Y-%m-%dT%H:%M:%SZ)") && why.ends_with("or pass all to read every row"), "{missing:?}: {why}");
    }
    let why = since_from(Some("2026-10-18T12:00:01Z"), now).unwrap_err();
    assert!(why.starts_with("AI_ENV_CURSOR_SINCE=\"2026-10-18T12:00:01Z\" is in the future (now 2026-10-18T12:00:00Z)"), "{why}");
    for bad in ["yesterday", "2026-10-14", "ALL", "1760432400"] {
        let why = since_from(Some(bad), now).unwrap_err();
        assert!(why.contains("an RFC 3339 UTC time, such as 2026-10-14T09:00:00Z, or all"), "{bad}: {why}");
    }
}

/// S9 (L10): t8_6 (a)'s chain, offline: the newest `drop_transport` row
/// since the step names the wrapper; its end row whose run holds the drop
/// shows `link_drops` and its spawn; that wrapper's own `agent_reconnect`
/// rows of that spawn come after the drop. Each broken link of the chain
/// is named: no drop, an end row of the pid that does not hold the drop,
/// no link lost, reconnects of another wrapper, of another spawn, or
/// before the drop.
#[test]
fn reconnect_evidence_chains_the_drop_to_its_wrapper() {
    let t = |ts: &str| ai_env_cli::wire::time::parse_rfc3339_utc(ts).unwrap();
    let since = t("2026-10-18T10:00:00Z") * 1000;
    let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let drop_row = |ts: &str, pid: u32| serde_json::json!({"v": 1, "ts": ts, "event": "drop_transport", "session_id": sid, "pid": 777, "detail": {"session": sid, "wrapper_pid": pid.to_string()}});
    let reconnect = |ts: &str, pid: u32, spawn: &str| serde_json::json!({"v": 1, "ts": ts, "event": "agent_reconnect", "session_id": null, "pid": pid, "detail": {"id": "microvm-a", "spawn": spawn, "reason": "closed", "ms": "420"}});
    let end_row = |pid: u32, start: &str, end: &str, drops: u32, spawn: &str| serde_json::json!({"pid": pid, "start": t(start) * 1000, "end": t(end) * 1000, "exit": 0, "note": format!("mode:remote(config); end:eof; vm:microvm-a; spawn:{spawn}; link_drops:{drops}; close_ms:600; pid_rewrite:ok")});
    let census = vec![
        // The same pid on an earlier day (a reused pid): its run does not hold the drop.
        end_row(4242, "2026-10-17T10:00:00Z", "2026-10-17T10:30:00Z", 1, "sp-old"),
        end_row(4242, "2026-10-18T10:05:00Z", "2026-10-18T10:20:00Z", 1, "sp-1"),
        end_row(4343, "2026-10-18T10:05:00Z", "2026-10-18T10:20:00Z", 0, "sp-2"),
    ];
    let drops = vec![drop_row("2026-10-18T09:00:00Z", 4343), drop_row("2026-10-18T10:10:00Z", 4242)];
    let reconnects = vec![reconnect("2026-10-18T10:06:00Z", 4242, "sp-1"), reconnect("2026-10-18T10:10:00Z", 4242, "sp-1"), reconnect("2026-10-18T10:11:00Z", 4343, "sp-1")];
    let (end, evidence) = reconnect_evidence(&census, &drops, &reconnects, since).unwrap();
    assert_eq!(end, census[1], "the end row whose run holds the drop");
    assert_eq!(evidence, format!("session {sid}: wrapper pid 4242, spawn sp-1, dropped at \"2026-10-18T10:10:00Z\", link_drops 1, 1 reconnect(s) at or after it"));
    assert_closed_well(&end);
    // Each broken link, named.
    let err = |census: &[Value], drops: &[Value], reconnects: &[Value]| reconnect_evidence(census, drops, reconnects, since).unwrap_err();
    assert!(err(&census, &drops[..1], &reconnects).starts_with("no drop_transport audit row since AI_ENV_CURSOR_SINCE"), "the only drop is before the step");
    assert!(err(&census[..1], &drops, &reconnects).starts_with("no census end row of wrapper pid 4242 whose run holds the drop at \"2026-10-18T10:10:00Z\""));
    let mut lost_none = census.clone();
    lost_none[1] = end_row(4242, "2026-10-18T10:05:00Z", "2026-10-18T10:20:00Z", 0, "sp-1");
    assert!(err(&lost_none, &drops, &reconnects).contains("shows link_drops 0"));
    assert_eq!(err(&census, &drops, &reconnects[2..]), "no agent_reconnect audit row of wrapper pid 4242", "another wrapper's reconnect");
    assert!(err(&census, &drops, &[reconnect("2026-10-18T10:12:00Z", 4242, "sp-9")]).contains("carries spawn sp-1 at or after the drop"), "another spawn");
    assert!(err(&census, &drops, &reconnects[..1]).contains("carries spawn sp-1 at or after the drop"), "before the drop");
    let mut no_pid = drops.clone();
    no_pid[1]["detail"]["wrapper_pid"] = serde_json::json!("x");
    assert!(err(&census, &no_pid, &reconnects).starts_with("the drop_transport row names no wrapper pid"));
    // `all` (0) reads the earlier drop too: the newest one still decides.
    assert_eq!(reconnect_evidence(&census, &drops, &reconnects, 0).unwrap().0, census[1]);
}
