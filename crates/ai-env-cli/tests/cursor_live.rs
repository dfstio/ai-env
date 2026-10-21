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
//! S10 (part B's B4, in a `target/s8` fixture window whose folder goes in
//! `WORKSPACE`, never the development chat): `t10_2` to `t10_5` and `t10_p`
//! chain the audit's rows (`session_move`, `session_move_end`,
//! `session_park`, `session_unpark`, `agent_reconnect`, `transcript_pull`,
//! `transcript_push`, `session_remote_end`), in the order they were
//! written, to the census end rows of their wrappers; T10.4 also reads the
//! VM rows and the workspace rows (`state/vms`, `state/workspaces`) through
//! the library, as no command prints them without asking AWS. Each chain is
//! a pure reader with an offline test.
//!
//! Each test is `#[ignore]`d and skips, saying why, unless
//! `AI_ENV_CURSOR_TESTS=1` and `AI_ENV_CURSOR_STEP` names its step (`t8_3`
//! to `t8_7`, `t9_s3`, `t10_2` to `t10_5`, `t10_p`):
//! `make test-cursor STEP=t8_3 SINCE=…` runs
//! `AI_ENV_CURSOR_TESTS=1 AI_ENV_CURSOR_STEP=t8_3 AI_ENV_CURSOR_SINCE=…
//! cargo test -p ai-env-cli --features bridge --test cursor_live --
//! --ignored --nocapture`. `AI_ENV_CURSOR_SINCE` is required (S9, L10): an
//! RFC 3339 UTC time no later than now (only rows at or after it: the
//! step's start, so evidence of an earlier step never passes for this one),
//! or `all` to read every row. `AI_ENV_CURSOR_WORKSPACE`, optional, is the
//! workspace of the chats (default: this checkout). The gated checks are
//! never part of `make test`; the readers' own offline tests are.

use ai_env_cli::bridge::config::Paths;
use ai_env_cli::bridge::remote::link::{LossCause, MigrateTrigger, MoveKind};
use ai_env_cli::bridge::remote::{audit_event, census_part};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The steps, as `AI_ENV_CURSOR_STEP` names them (S9: `t9_s3`, the S3 store's chats; S10: `t10_2` to `t10_5` and
/// `t10_p`, the continuity steps and the placeholder's picker reopen).
const STEPS: [&str; 11] = ["t8_3", "t8_4", "t8_5", "t8_6", "t8_7", "t9_s3", "t10_2", "t10_3", "t10_4", "t10_5", "t10_p"];

/// The remote sessions' mode notes (`remote::MODE_NOTES`).
const REMOTE_MODES: [&str; 2] = ["mode:remote", "mode:remote(config)"];

/// T10.2's bound on a reopen onto the VM its closing suspend left (v6 §5, S10: the chat continues within 15 s):
/// the reopen's `init_ms`, from its census start to the forwarded `initialize` answer.
const REOPEN_BUDGET_MS: u64 = 15_000;

/// How an `agent_reconnect` row's reason begins after a sleep (`agent::session`'s clock checks): `woke after`
/// when the wall clock ran on while the monotonic one stood still (the Mac slept: a lid closed), `no frame for`
/// when both ran on and no frame came (the wrapper stopped: T10.2's SIGSTOP stand-in).
const SLEEP_REASONS: [&str; 2] = ["woke after", "no frame for"];

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

/// Every audit row written at or after `since` (Unix ms), in the order they were written: S10's chains read that
/// order, as their rows often share a second.
fn audit_since(since: u64) -> Vec<Value> {
    let paths = Paths::resolve().expect("the bridge root");
    let rows = ai_env_cli::bridge::audit::read_rows(&paths.audit(), None).expect("the audit");
    rows.into_iter().filter(|r| at_ms(r).is_some_and(|t| t >= since)).collect()
}

/// An audit row's time, the start of its second (`ts`), in Unix ms.
fn at_ms(row: &Value) -> Option<u64> {
    row["ts"].as_str().and_then(ai_env_cli::wire::time::parse_rfc3339_utc).map(|s| s * 1000)
}

/// The detail value `key` of an audit row (every detail value is a string).
fn detail<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row["detail"][key].as_str()
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

/// The first of `candidates` (newest first) that `check` passes; else the first one's `Err` (what the newest
/// lacks), or `none()` when there is no candidate at all.
fn first_passing<T, R>(candidates: impl IntoIterator<Item = T>, none: impl FnOnce() -> String, mut check: impl FnMut(T) -> Result<R, String>) -> Result<R, String> {
    let mut why = None;
    for candidate in candidates {
        match check(candidate) {
            Ok(found) => return Ok(found),
            Err(e) => {
                why.get_or_insert(e);
            }
        }
    }
    Err(why.unwrap_or_else(none))
}

/// Whether a census row ran in `ws` (its cwd there or below).
fn in_ws(row: &Value, ws: &Path) -> bool {
    row["cwd"].as_str().is_some_and(|c| Path::new(c).starts_with(ws))
}

/// The end row of wrapper `pid` whose run holds the second that starts at `at` (Unix ms, an audit row's time):
/// started by that second's end and ended at or after its start; the newest start should a reused pid match twice.
fn run_holding(census: &[Value], pid: u64, at: u64) -> Option<&Value> {
    census.iter().filter(|r| r["pid"].as_u64() == Some(pid) && r["start"].as_u64().is_some_and(|s| s < at + 1000) && r["end"].as_u64().is_some_and(|e| e >= at)).max_by_key(|r| r["start"].as_u64())
}

/// The chat an end row's run served: its `--resume` id, else (a new chat's argv names none) the `session_id` of
/// the `session_remote_end` audit row its wrapper wrote right after it, within a minute of the run's end.
fn served(row: &Value, audit: &[Value]) -> Option<String> {
    if let Some(id) = resumed(row) {
        return Some(id);
    }
    let (pid, end) = (row["pid"].as_u64()?, row["end"].as_u64()?);
    audit
        .iter()
        .filter(|r| r["event"] == audit_event::SESSION_REMOTE_END && r["pid"].as_u64() == Some(pid) && at_ms(r).is_some_and(|t| t + 999 >= end && t <= end + 60_000))
        .find_map(|r| r["session_id"].as_str().map(str::to_string))
}

/// An end row's moves by kind (S10 §4.1, `moves:readdress=<n>,respawn=<n>,migrate=<n>`), in that order; `None`
/// without the part (no move started) or with a kind or count that does not parse.
fn moves(row: &Value) -> Option<[u32; 3]> {
    let kinds = [MoveKind::Readdress, MoveKind::Respawn, MoveKind::Migrate].map(MoveKind::word);
    let mut n = [0; 3];
    for kv in part(row, census_part::MOVES)?.split(',') {
        let (kind, count) = kv.split_once('=')?;
        n[kinds.iter().position(|k| *k == kind)?] = count.parse().ok()?;
    }
    Some(n)
}

/// An end row's `inits:` or `echoes:` part (S10 §4.1, `<forwarded>/<swallowed>`) as its two counts.
fn forwarded_swallowed(row: &Value, name: &str) -> Option<(u64, u64)> {
    let counts = part(row, name)?;
    let (forwarded, swallowed) = counts.split_once('/')?;
    Some((forwarded.parse().ok()?, swallowed.parse().ok()?))
}

/// A note part's value for an evidence line, `-` when the row has none.
fn shown(row: &Value, name: &str) -> String {
    part(row, name).unwrap_or_else(|| "-".to_string())
}

/// T10.2's chain (S10), pure: since `since` (Unix ms), in `ws`, a chat
/// reopened from the picker (an end row with `--resume`) onto the VM its
/// closing suspend left (`vm_how:resumed`), its `initialize` answered
/// within [`REOPEN_BUDGET_MS`] (`init_ms`); the same chat's end row before
/// it on that VM (the close, [`served`]: a config probe's end row names no
/// chat); and an `agent_reconnect` audit row of either run's wrapper
/// (`pid`), carrying that run's spawn and written during it, after a sleep
/// ([`SLEEP_REASONS`]: `woke after` for the lid, `no frame for` for the
/// SIGSTOP stand-in), that run's end row showing `link_drops` of 1 or more.
/// `Ok`: the close's and the reopen's end rows (for [`assert_closed_well`])
/// and the evidence in one line; `Err`: what the newest reopen lacks, or
/// that there is none.
fn reopen_evidence(census: &[Value], audit: &[Value], ws: &Path, since: u64) -> Result<(Value, Value, String), String> {
    use census_part::{CLOSE_MS, LINK_DROPS, SPAWN, VM, VM_HOW};
    let ends = remote_ends(census, ws, since);
    let reopens = ends.iter().rev().filter(|r| resumed(r).is_some() && part(r, VM_HOW).as_deref() == Some("resumed"));
    let none = || format!("no chat of {} reopened from the picker onto its suspended VM since AI_ENV_CURSOR_SINCE (a remote end row with --resume and vm_how:resumed): close a chat, let the closing suspend run, then reopen it from the picker", ws.display());
    first_passing(reopens, none, |reopen| {
        let (id, vm, pid) = (resumed(reopen).unwrap_or_default(), shown(reopen, VM), reopen["pid"].as_u64().unwrap_or(0));
        let init_ms = part(reopen, "init_ms").and_then(|ms| ms.parse::<u64>().ok()).ok_or_else(|| format!("the reopen of {id} (wrapper pid {pid}) on {vm} never answered initialize (no init_ms)"))?;
        if init_ms >= REOPEN_BUDGET_MS {
            return Err(format!("the reopen of {id} (wrapper pid {pid}) on {vm} answered initialize after {init_ms} ms (T10.2: under {REOPEN_BUDGET_MS} ms)"));
        }
        let start = reopen["start"].as_u64().unwrap_or(0);
        let close = ends
            .iter()
            .filter(|c| c["end"].as_u64().is_some_and(|e| e <= start) && part(c, VM).as_deref() == Some(vm.as_str()) && served(c, audit).as_deref() == Some(id.as_str()))
            .max_by_key(|c| c["end"].as_u64())
            .ok_or_else(|| format!("no end row of {id} on {vm} before its reopen (wrapper pid {pid}) since AI_ENV_CURSOR_SINCE: the close (a run whose --resume, or whose wrapper's session_remote_end audit row, names the chat)"))?;
        let slept = [reopen, close].into_iter().find_map(|run| {
            let (rpid, spawn, from, to) = (run["pid"].as_u64()?, part(run, SPAWN)?, run["start"].as_u64()?, run["end"].as_u64()?);
            audit
                .iter()
                .rev()
                .find(|a| a["event"] == "agent_reconnect" && a["pid"].as_u64() == Some(rpid) && detail(a, "spawn") == Some(spawn.as_str()) && detail(a, "reason").is_some_and(|w| SLEEP_REASONS.iter().any(|p| w.starts_with(p))) && at_ms(a).is_some_and(|t| t + 999 >= from && t <= to))
                .map(|a| (run, a))
        });
        let Some((run, row)) = slept else {
            return Err(format!("no agent_reconnect audit row of {id}'s close (wrapper pid {}) or reopen (wrapper pid {pid}) after a sleep (its reason starting woke after, the lid, or no frame for, the wrapper stopped) carrying that run's spawn during it: close the lid for 3 minutes during a turn", close["pid"]));
        };
        let drops = part(run, LINK_DROPS).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
        if drops < 1 {
            return Err(format!("the run of {id} that slept (wrapper pid {}) shows link_drops {drops}: the sleep at {} lost no link", run["pid"], row["ts"]));
        }
        let evidence = format!(
            "session {id}: closed by wrapper pid {} on {vm} (end:{}, close_ms {}), reopened by wrapper pid {pid} (vm_how:resumed, init_ms {init_ms}, under {REOPEN_BUDGET_MS}); wrapper pid {} slept ({} at {}, spawn {}), link_drops {drops}",
            close["pid"],
            shown(close, "end"),
            shown(close, CLOSE_MS),
            run["pid"],
            detail(row, "reason").unwrap_or_default(),
            row["ts"],
            detail(row, "spawn").unwrap_or_default()
        );
        Ok((close.clone(), reopen.clone(), evidence))
    })
}

/// T10.3's chain (S10), pure: since `since` (Unix ms), a `session_move`
/// audit row of a live re-address off a terminated VM (`kind` readdress,
/// `cause` vm_gone, `gen` 2 or more: a reopen's carry is generation 1);
/// the end row of its wrapper (`pid`) whose run holds it, in `ws`, counting
/// it in `moves` (`readdress` 1 or more) and showing the moved generation's
/// `initialize` swallowed once (`inits:<n>/1`: the host saw one init for
/// the turn sent again). Its `session_move_end`, when written (that
/// wrapper's first after it, before its next move: a cut miss's retry
/// writes the move's one row under the retry's generation), names where it
/// went. `Ok`: that end row (for [`assert_closed_well`]) and the evidence
/// in one line; `Err`: what the newest such move lacks, or that there is
/// none.
fn readdress_evidence(census: &[Value], audit: &[Value], ws: &Path, since: u64) -> Result<(Value, String), String> {
    use census_part::{CUT, ECHOES, INITS, MOVES, MOVE_MS, VM};
    let (kind, cause) = (MoveKind::Readdress.word(), LossCause::VmGone.word());
    let moved = audit.iter().enumerate().rev().filter(|(_, r)| r["event"] == audit_event::SESSION_MOVE && at_ms(r).is_some_and(|t| t >= since) && detail(r, "kind") == Some(kind) && detail(r, "cause") == Some(cause) && detail(r, "gen").and_then(|g| g.parse::<u32>().ok()).is_some_and(|g| g >= 2));
    let none = || "no session_move audit row of kind readdress whose cause is vm_gone (a live move, generation 2 or more: a reopen's carry is generation 1) since AI_ENV_CURSOR_SINCE: ai-env vm terminate the chat's VM during a turn in Cursor (T10.3)".to_string();
    first_passing(moved, none, |(i, mv)| {
        let pid = mv["pid"].as_u64().ok_or_else(|| format!("the session_move row names no pid: {mv}"))?;
        let (session, gen, from) = (detail(mv, "session").unwrap_or("-"), detail(mv, "gen").unwrap_or("-"), detail(mv, "from_vm").unwrap_or("-"));
        let end = run_holding(census, pid, at_ms(mv).unwrap_or_default()).ok_or_else(|| format!("no census end row of wrapper pid {pid} whose run holds its move at {}: close the chat (or reload Cursor), then check", mv["ts"]))?;
        if !in_ws(end, ws) {
            return Err(format!("the chat that moved at {} (wrapper pid {pid}) ran in {}, not in {} (AI_ENV_CURSOR_WORKSPACE)", mv["ts"], end["cwd"], ws.display()));
        }
        if moves(end).is_none_or(|n| n[0] < 1) {
            return Err(format!("the end row of wrapper pid {pid} shows moves:{} where the re-address counts (readdress=1 or more)", shown(end, MOVES)));
        }
        if forwarded_swallowed(end, INITS).is_none_or(|(forwarded, swallowed)| forwarded < 1 || swallowed != 1) {
            return Err(format!("the end row of wrapper pid {pid} shows inits:{} where the moved generation's init, swallowed once, reads inits:<n>/1", shown(end, INITS)));
        }
        let ours = |event: &str, r: &Value| r["event"] == event && r["pid"].as_u64() == Some(pid);
        let went = audit[i + 1..]
            .iter()
            .take_while(|r| !ours(audit_event::SESSION_MOVE, r))
            .find(|r| ours(audit_event::SESSION_MOVE_END, r))
            .map_or_else(|| "-".to_string(), |r| format!("{} to {}", detail(r, "outcome").unwrap_or("-"), detail(r, "to_vm").unwrap_or("-")));
        let evidence = format!(
            "session {session}: wrapper pid {pid} moved it off {from} at {} (gen {gen}, readdress, vm_gone; its end: {went}); the end row on {}: moves:{}, move_ms:{}, cut:{}, inits:{}, echoes:{}",
            mv["ts"],
            shown(end, VM),
            shown(end, MOVES),
            shown(end, MOVE_MS),
            shown(end, CUT),
            shown(end, INITS),
            shown(end, ECHOES)
        );
        Ok((end.clone(), evidence))
    })
}

/// T10.4's chain (S10), pure: since `since` (Unix ms), either (a) a wall
/// migration: a `session_move_end` audit row of kind migrate, done, and
/// its `session_move` before it (the same wrapper and generation: phase
/// B's) whose trigger is the wall; the end row of that wrapper whose run
/// holds the move, in `ws`, counting it (`moves` migrate 1 or more); the
/// old VM's row (`vm_rows`, as `registry::view` shows one) terminated by
/// migrate; the move's seed from the old VM's last fetch (`seed` box); and
/// a workspace row (`ws_rows`) recording the new VM seeded at or after the
/// move's start (`seeded_at`: a kept seed rewrites no entry, so a reused
/// VM's earlier seed is never this one) with a WIP snapshot (`seeded_wip`:
/// the edit that fetch brought); or else (b) a reopen that carried its
/// chat off its VM first (an end row in `ws` with `--resume` and
/// `carried:migrate`, near the wall, or `carried:readdress`, past it).
/// `Ok`: the chat's end row (for [`assert_closed_well`]) and the evidence
/// in one line; `Err`: what the newest wall migration lacks, and that no
/// reopen carried a chat.
fn migration_evidence(census: &[Value], audit: &[Value], vm_rows: &[Value], ws_rows: &[Value], ws: &Path, since: u64) -> Result<(Value, String), String> {
    use census_part::{CARRIED, MOVES, SEED, TRANSCRIPT, VM, VM_HOW};
    let (migrate, wall) = (MoveKind::Migrate.word(), MigrateTrigger::Wall { left_s: 0 }.word());
    let done = audit.iter().enumerate().rev().filter(|(_, r)| r["event"] == audit_event::SESSION_MOVE_END && at_ms(r).is_some_and(|t| t >= since) && detail(r, "kind") == Some(migrate) && detail(r, "outcome") == Some("done"));
    let none = || "no migration done since AI_ENV_CURSOR_SINCE (a session_move_end audit row of kind migrate, outcome done)".to_string();
    let walled = first_passing(done, none, |(i, moved)| {
        let pid = moved["pid"].as_u64().ok_or_else(|| format!("the session_move_end row names no pid: {moved}"))?;
        let (gen, from, to) = (detail(moved, "gen").unwrap_or("-"), detail(moved, "from_vm").unwrap_or("-"), detail(moved, "to_vm").unwrap_or("-"));
        let start = audit[..i]
            .iter()
            .rev()
            .find(|r| r["event"] == audit_event::SESSION_MOVE && r["pid"].as_u64() == Some(pid) && detail(r, "gen") == Some(gen) && detail(r, "kind") == Some(migrate))
            .ok_or_else(|| format!("the migration of wrapper pid {pid} off {from} (gen {gen}) has no session_move row before its end at {}", moved["ts"]))?;
        let trigger = detail(start, "trigger").unwrap_or("-");
        if trigger != wall {
            return Err(format!("the migration of wrapper pid {pid} off {from} at {} was triggered by {trigger}, not the wall: T10.4 (a) waits for the wall's margin (migrate_before_wall_s)", start["ts"]));
        }
        let end = run_holding(census, pid, at_ms(start).unwrap_or_default()).ok_or_else(|| format!("no census end row of wrapper pid {pid} whose run holds its migration at {}: close the chat (or reload Cursor), then check", start["ts"]))?;
        if !in_ws(end, ws) {
            return Err(format!("the chat that migrated at {} (wrapper pid {pid}) ran in {}, not in {} (AI_ENV_CURSOR_WORKSPACE)", start["ts"], end["cwd"], ws.display()));
        }
        if moves(end).is_none_or(|n| n[2] < 1) {
            return Err(format!("the end row of wrapper pid {pid} shows moves:{} where the migration counts (migrate=1 or more)", shown(end, MOVES)));
        }
        let old = vm_rows.iter().find(|v| v["id"].as_str() == Some(from)).ok_or_else(|| format!("the old VM {from} has no row in state/vms (gc removes a terminated row after 7 days)"))?;
        let by = old["terminated_by"].as_str().unwrap_or("-");
        if by != migrate {
            return Err(format!("the old VM {from}'s row says terminated_by {by} (status {}): the migration's terminate, by migrate once the new VM's spawn started, did not mark it", old["status"]));
        }
        let seed = detail(moved, "seed").unwrap_or("-");
        if seed != "box" {
            // `kept` under a carry is C1's occupied: phase A reused a VM another chat's checkout changed.
            let fix = if seed == "kept" {
                format!("{to} was reused and kept another chat's changed checkout (occupied): terminate the workspace's other suspended VMs, then run T10.4 (a) again")
            } else {
                "leave an uncommitted edit in the chat before the wall (T10.4 (a))".to_string()
            };
            return Err(format!("the migration of wrapper pid {pid} seeded {to} from {seed}, not from {from}'s last fetch (seed box): {fix}"));
        }
        // In seconds, as `seeded_at` is: phase B's seed follows its `session_move`, in that second or later.
        let moved_s = at_ms(start).unwrap_or_default() / 1000;
        let wip = ws_rows
            .iter()
            .find_map(|w| {
                let entry = &w["vm"][to];
                entry["seeded_at"].as_u64().filter(|s| *s >= moved_s).and_then(|_| entry["seeded_wip"].as_str()).filter(|c| !c.is_empty())
            })
            .ok_or_else(|| format!("no workspace row records the new VM {to} seeded with a WIP snapshot at or after the migration's start at {} (seeded_wip, seeded_at): leave an uncommitted edit before the wall (T10.4 (a))", start["ts"]))?;
        let evidence = format!(
            "a wall migration: wrapper pid {pid} moved session {} off {from} to {to} at {} (gen {gen}, how {}, seed {}, transcript {}); {from} terminated by migrate (leaving_for {}); {to} seeded with the WIP {wip}; the end row: moves:{}",
            detail(moved, "session").unwrap_or("-"),
            moved["ts"],
            detail(moved, "how").unwrap_or("-"),
            detail(moved, "seed").unwrap_or("-"),
            detail(moved, "transcript").unwrap_or("-"),
            old["leaving_for"].as_str().unwrap_or("-"),
            shown(end, MOVES)
        );
        Ok((end.clone(), evidence))
    });
    let why = match walled {
        Ok(found) => return Ok(found),
        Err(why) => why,
    };
    let Some(end) = remote_ends(census, ws, since).into_iter().rev().find(|r| resumed(r).is_some() && part(r, CARRIED).is_some()) else {
        return Err(format!("{why}; nor did a reopen carry a chat off its VM in {} since AI_ENV_CURSOR_SINCE (an end row with --resume and carried:migrate, near the wall, or carried:readdress, past it)", ws.display()));
    };
    let evidence = format!(
        "a reopen's carry: session {} reopened by wrapper pid {} carried:{} onto {} (vm_how:{}, seed:{}, transcript:{}, moves:{})",
        resumed(&end).unwrap_or_default(),
        end["pid"],
        shown(&end, CARRIED),
        shown(&end, VM),
        shown(&end, VM_HOW),
        shown(&end, SEED),
        shown(&end, TRANSCRIPT),
        shown(&end, MOVES)
    );
    Ok((end, evidence))
}

/// T10.5's chain (S10), pure: since `since` (Unix ms), in the order the
/// audit's rows were written: a park at a permission prompt
/// (`session_park`, `why` prompt) and its unpark by the answer (that
/// spawn's `session_unpark` after it, `by` control_response); then a move
/// of that wrapper's chat (`session_move`) and its end (that wrapper's
/// first `session_move_end` after it, before its next move: a cut miss's
/// retry writes the move's one row under the retry's generation; done: the
/// new VM); then a subtree pull, a `transcript_pull` of the chat into the
/// new VM by that wrapper, written, from the move's start on, beyond the
/// main transcript's one restore (unless the move's `transcript` is kept
/// or none: a missing or unknown word counts one): the subagents' files
/// follow the spawn. The end row of the wrapper whose run
/// holds the move is in `ws`. `Ok`: that end row (for
/// [`assert_closed_well`]) and the evidence in one line; `Err`: what the
/// newest move lacks, or that there is none.
fn park_evidence(census: &[Value], audit: &[Value], ws: &Path, since: u64) -> Result<(Value, String), String> {
    use audit_event::{SESSION_MOVE, SESSION_MOVE_END, SESSION_PARK, SESSION_UNPARK, TRANSCRIPT_PULL};
    use census_part::{MOVES, PARK, UNPARK_RESUMED};
    let rows: Vec<&Value> = audit.iter().filter(|r| at_ms(r).is_some_and(|t| t >= since)).collect();
    let moved = rows.iter().enumerate().rev().filter(|(_, r)| r["event"] == SESSION_MOVE);
    let none = || "no session_move audit row since AI_ENV_CURSOR_SINCE: after the park and a Task-tool turn, ai-env vm terminate the chat's VM, then send the next message (T10.5's move)".to_string();
    first_passing(moved, none, |(p, &mv)| {
        let pid = mv["pid"].as_u64().ok_or_else(|| format!("the session_move row names no pid: {mv}"))?;
        let ours = |event: &str, r: &Value| r["event"] == event && r["pid"].as_u64() == Some(pid);
        let (before, after) = (&rows[..p], &rows[p + 1..]);
        let (park, unpark) = before
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, r)| ours(SESSION_UNPARK, r) && detail(r, "by") == Some("control_response"))
            .find_map(|(q, &unpark)| {
                let spawn = detail(unpark, "spawn")?;
                let park = before[..q].iter().rev().find(|r| ours(SESSION_PARK, r) && detail(r, "spawn") == Some(spawn))?;
                (detail(park, "why") == Some("prompt")).then_some((*park, unpark))
            })
            .ok_or_else(|| format!("wrapper pid {pid} parked at no prompt before its move at {} (a session_park row with why prompt, then that spawn's session_unpark by control_response, the answer): leave the permission prompt unanswered past park_after_s and max_idle_s, then answer it", mv["ts"]))?;
        let (session, gen) = (detail(mv, "session").unwrap_or("-"), detail(mv, "gen").unwrap_or("-"));
        let done = after.iter().take_while(|r| !ours(SESSION_MOVE, r)).find(|r| ours(SESSION_MOVE_END, r)).ok_or_else(|| format!("the move of wrapper pid {pid} at {} (gen {gen}) has no session_move_end row: its claude never started on the new VM", mv["ts"]))?;
        let outcome = detail(done, "outcome").unwrap_or("-");
        if outcome != "done" {
            return Err(format!("the move of wrapper pid {pid} at {} (gen {gen}) ended {outcome}, not done", mv["ts"]));
        }
        let to = detail(done, "to_vm").unwrap_or("-");
        let pulled = after.iter().filter(|r| ours(TRANSCRIPT_PULL, r) && detail(r, "session") == Some(session) && detail(r, "vm") == Some(to) && detail(r, "outcome") == Some("written")).count();
        let main = usize::from(!matches!(detail(done, "transcript"), Some("kept" | "none")));
        let subtree = pulled.saturating_sub(main);
        if subtree == 0 {
            return Err(format!(
                "no subtree pull into {to} after the move of wrapper pid {pid} at {}: {pulled} transcript_pull row(s) of {session} written there, the main transcript's {main} (transcript:{}): run a Task-tool turn and wait for its sync before the terminate",
                mv["ts"],
                detail(done, "transcript").unwrap_or("-")
            ));
        }
        let end = run_holding(census, pid, at_ms(mv).unwrap_or_default()).ok_or_else(|| format!("no census end row of wrapper pid {pid} whose run holds its move at {}: close the chat (or reload Cursor), then check", mv["ts"]))?;
        if !in_ws(end, ws) {
            return Err(format!("the chat that moved at {} (wrapper pid {pid}) ran in {}, not in {} (AI_ENV_CURSOR_WORKSPACE)", mv["ts"], end["cwd"], ws.display()));
        }
        let evidence = format!(
            "session {session}: wrapper pid {pid} parked spawn {} on {} at a prompt at {} (quiet_ms {}), unparked by the answer at {} (vm_state {}, {} ms); moved off {} to {to} at {} ({}, gen {gen}); {subtree} subtree pull(s) into {to} beside the main transcript's {main}; the end row: park:{}, unpark_resumed:{}, moves:{}",
            detail(park, "spawn").unwrap_or("-"),
            detail(park, "vm").unwrap_or("-"),
            park["ts"],
            detail(park, "quiet_ms").unwrap_or("-"),
            unpark["ts"],
            detail(unpark, "vm_state").unwrap_or("-"),
            detail(unpark, "ms").unwrap_or("-"),
            detail(mv, "from_vm").unwrap_or("-"),
            mv["ts"],
            detail(mv, "kind").unwrap_or("-"),
            shown(end, PARK),
            shown(end, UNPARK_RESUMED),
            shown(end, MOVES)
        );
        Ok((end.clone(), evidence))
    })
}

/// The placeholder's picker reopen (S10 F11, S9's left-over check), pure:
/// since `since` (Unix ms), in `ws`, a new chat's first end row (no
/// `--resume`; its chat named by its wrapper's `session_remote_end` audit
/// row, [`served`]) that closed before any `transcript_push` of that chat
/// (none at or before its end: the Mac held only the placeholder view,
/// `Remote chat`), then a reopen of it from the picker (`--resume`) on
/// that same VM (both end rows naming it, `vm:`) with its transcript kept
/// there (`transcript:kept`), inside its wall: not carried off it
/// (`carried:`, a reopen near or past the wall). `Ok`: the first run's and
/// the reopen's end rows and the evidence in one line; `Err`: what the
/// newest kept reopen lacks, or that there is none.
fn placeholder_evidence(census: &[Value], audit: &[Value], ws: &Path, since: u64) -> Result<(Value, Value, String), String> {
    use census_part::{CARRIED, CLOSE_MS, TRANSCRIPT, VM, VM_HOW};
    let ends = remote_ends(census, ws, since);
    let kept = ends.iter().rev().filter(|r| resumed(r).is_some() && part(r, TRANSCRIPT).as_deref() == Some("kept") && part(r, CARRIED).is_none());
    let none = || format!("no chat of {} reopened from the picker with its transcript kept on its VM since AI_ENV_CURSOR_SINCE (a remote end row with --resume and transcript:kept, not carried:): open a new chat, close it before its first sync, then reopen it from the picker while its VM is still reusable", ws.display());
    first_passing(kept, none, |reopen| {
        let (id, pid) = (resumed(reopen).unwrap_or_default(), reopen["pid"].as_u64().unwrap_or(0));
        let vm = part(reopen, VM).ok_or_else(|| format!("{id} was reopened kept (wrapper pid {pid}) but its end row names no VM"))?;
        let start = reopen["start"].as_u64().unwrap_or(0);
        let first = ends
            .iter()
            .filter(|f| resumed(f).is_none() && f["end"].as_u64().is_some_and(|e| e <= start) && served(f, audit).as_deref() == Some(id.as_str()))
            .min_by_key(|f| f["start"].as_u64())
            .ok_or_else(|| format!("{id} was reopened kept on {vm} (wrapper pid {pid}), but no new chat's end row before it served it since AI_ENV_CURSOR_SINCE (no --resume; its wrapper's session_remote_end audit row names the chat): open the new chat after the step's start"))?;
        if part(first, VM).as_deref() != Some(vm.as_str()) {
            return Err(format!("{id} began on {} (wrapper pid {}) and was reopened on {vm}: the reopen did not find its VM", shown(first, VM), first["pid"]));
        }
        let closed = first["end"].as_u64().unwrap_or(0);
        if let Some(push) = audit.iter().find(|r| r["event"] == audit_event::TRANSCRIPT_PUSH && detail(r, "session") == Some(id.as_str()) && at_ms(r).is_some_and(|t| t <= closed)) {
            return Err(format!("{id}'s first run (wrapper pid {}) synced before it closed (transcript_push at {}): close a new chat before its first sync", first["pid"], push["ts"]));
        }
        let evidence = format!(
            "session {id}: a new chat (wrapper pid {}) on {vm} closed before any transcript_push of it (end:{}, close_ms {}), then reopened from the picker by wrapper pid {pid} on {vm} (vm_how:{}, transcript:kept, init_ms {})",
            first["pid"],
            shown(first, "end"),
            shown(first, CLOSE_MS),
            shown(reopen, VM_HOW),
            shown(reopen, "init_ms")
        );
        Ok((first.clone(), reopen.clone(), evidence))
    })
}

/// Every workspace row (`state/workspaces/<slug>.toml`, read through the library: no command prints them), as
/// its JSON; a file that does not read is left out.
fn workspace_rows(paths: &Paths) -> Vec<Value> {
    let Ok(dir) = std::fs::read_dir(paths.workspaces()) else {
        return Vec::new();
    };
    dir.filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".toml")).map(str::to_string))
        .filter_map(|slug| ai_env_cli::bridge::workspace::rows::read(paths, &slug).ok())
        .flat_map(|rows| rows.ws.into_values())
        .filter_map(|row| serde_json::to_value(row).ok())
        .collect()
}

/// T10.2 (S10, B4): a chat closed well, its VM suspended by the closing
/// suspend, then reopened from the picker onto that VM (`vm_how:resumed`)
/// within 15 s, and a sleep during a turn (the lid closed for 3 minutes,
/// or the wrapper stopped) that cost a link and came back:
/// [`reopen_evidence`]. Both runs closed well.
#[test]
#[ignore = "live evidence after T10.2 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t10_2 SINCE=… WORKSPACE=…"]
fn t10_2_evidence() {
    if !chosen("t10_2") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let (close, reopen, evidence) = reopen_evidence(&census(), &audit_since(since), &ws, since).unwrap_or_else(|why| panic!("T10.2: {why}"));
    eprintln!("t10_2: {evidence}");
    assert_closed_well(&close);
    assert_closed_well(&reopen);
}

/// T10.3 (S10, B4): a chat whose VM was terminated during a turn moved to
/// a new VM by itself ([`readdress_evidence`]: the move's audit row, the
/// end row's `moves` and `inits:<n>/1`) and closed well; both dup probes
/// were recorded no-duplicate since the step; and `move-note` was recorded
/// `shown` (`probes::check_move_note_verdict`) beside the census's
/// evidence of a move (`probes::move_evidence`).
#[test]
#[ignore = "live evidence after T10.3 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t10_3 SINCE=… WORKSPACE=…"]
fn t10_3_evidence() {
    if !chosen("t10_3") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let census = census();
    let (end, evidence) = readdress_evidence(&census, &audit_since(since), &ws, since).unwrap_or_else(|why| panic!("T10.3: {why}"));
    eprintln!("t10_3: {evidence}");
    assert_closed_well(&end);
    for probe in ["dup-init", "dup-user-replay"] {
        let newest = lab_rows(probe, since).pop().unwrap_or_else(|| panic!("{probe}: nothing recorded since AI_ENV_CURSOR_SINCE (ai-env lab run {probe} --manual VERDICT, after the move)"));
        assert_eq!(newest["verdict"].as_str(), Some("no-duplicate"), "{probe}: {newest}");
    }
    let rows: Vec<Value> = census.into_iter().filter(|r| r["start"].as_u64().unwrap_or(0) >= since && in_ws(r, &ws)).collect();
    let moved = ai_env_cli::bridge::probes::move_evidence(&rows).unwrap_or_else(|why| panic!("move-note's evidence: {why}"));
    let note = lab_rows("move-note", since).pop().unwrap_or_else(|| panic!("move-note: nothing recorded since AI_ENV_CURSOR_SINCE (ai-env lab run move-note --manual VERDICT, after the move in Cursor)"));
    let verdict = note["verdict"].as_str().unwrap_or_default();
    ai_env_cli::bridge::probes::check_move_note_verdict(verdict).unwrap_or_else(|why| panic!("{why}: {note}"));
    assert_eq!(verdict, "shown", "move-note: Cursor did not show the move's informational line: {note}");
    eprintln!("t10_3: move-note {verdict}; {moved}");
}

/// T10.4 (S10): a wall migration between turns (the move's audit rows,
/// the old VM's row terminated by migrate, the new VM seeded with the
/// WIP), or a reopen that carried its chat off its VM first (`carried:`):
/// [`migration_evidence`]. The chat closed well.
#[test]
#[ignore = "live evidence after T10.4 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t10_4 SINCE=… WORKSPACE=…"]
fn t10_4_evidence() {
    use ai_env_cli::bridge::vm::registry;
    if !chosen("t10_4") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let paths = Paths::resolve().expect("the bridge root");
    let vm_rows: Vec<Value> = registry::list_rows(&paths).expect("the VM rows").iter().map(registry::view).collect();
    let (end, evidence) = migration_evidence(&census(), &audit_since(since), &vm_rows, &workspace_rows(&paths), &ws, since).unwrap_or_else(|why| panic!("T10.4: {why}"));
    eprintln!("t10_4: {evidence}");
    assert_closed_well(&end);
}

/// T10.5 (S10, B4): a chat parked at a permission prompt and unparked by
/// the answer, then moved to a new VM, its subagents' files pulled into it
/// after the main transcript: [`park_evidence`]. It closed well. That the
/// tool ran and the subagents' files are on the new VM's disk is checked
/// by hand (`vm exec ls`).
#[test]
#[ignore = "live evidence after T10.5 in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t10_5 SINCE=… WORKSPACE=…"]
fn t10_5_evidence() {
    if !chosen("t10_5") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let (end, evidence) = park_evidence(&census(), &audit_since(since), &ws, since).unwrap_or_else(|why| panic!("T10.5: {why}"));
    eprintln!("t10_5: {evidence}");
    assert_closed_well(&end);
}

/// F11 (S10, B4): a new chat closed before its first sync, then reopened
/// from the picker on its VM with its transcript kept:
/// [`placeholder_evidence`]. The reopen closed well; the first run may
/// have closed mid-turn (`end:eof_kill`). Cursor's picker listing `Remote
/// chat` is seen by hand.
#[test]
#[ignore = "live evidence after the placeholder's reopen in Cursor: AI_ENV_CURSOR_TESTS=1 make test-cursor STEP=t10_p SINCE=… WORKSPACE=…"]
fn t10_p_evidence() {
    if !chosen("t10_p") {
        return;
    }
    let (ws, since) = (workspace(), since_of());
    let (_, reopen, evidence) = placeholder_evidence(&census(), &audit_since(since), &ws, since).unwrap_or_else(|why| panic!("the placeholder's reopen: {why}"));
    eprintln!("t10_p: {evidence}");
    assert_closed_well(&reopen);
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

/// The workspace of the S10 readers' offline tests (a `target/s8` fixture's).
const FIXTURE_WS: &str = "/Users/mike/Documents/DeFi/ai-env/target/s8/w";

/// S10 (T10.2): the reopen's chain, offline. The newest reopen onto a
/// resumed VM within 15 s; the same chat's close before it on that VM,
/// named by its wrapper's `session_remote_end` row (a config probe's end
/// row on the VM names no chat, so it is never the close); a reconnect
/// after a sleep (`woke after`, or `no frame for`) of either run's wrapper
/// and spawn, during that run, which lost a link. Each broken link is
/// named.
#[test]
fn reopen_evidence_chains_the_close_the_reopen_and_the_sleep() {
    let t = |ts: &str| ai_env_cli::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
    let (ws, since) = (Path::new(FIXTURE_WS), t("2026-10-20T10:00:00Z"));
    let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let end_row = |pid: u32, start: &str, end: &str, resume: Option<&str>, note: &str| {
        let argv: Vec<&str> = ["/x/ai-env-claude", "/x/claude"].into_iter().chain(resume.map(|id| ["--resume", id]).into_iter().flatten()).collect();
        serde_json::json!({"pid": pid, "start": t(start), "end": t(end), "exit": 0, "cwd": FIXTURE_WS, "argv": argv, "note": format!("mode:remote; {note}")})
    };
    let row = |ts: &str, event: &str, pid: u32, session: Option<&str>, detail: Value| serde_json::json!({"v": 1, "ts": ts, "event": event, "session_id": session, "pid": pid, "detail": detail});
    let remote_end = |ts: &str, pid: u32, session: Option<&str>, spawn: &str| row(ts, "session_remote_end", pid, session, serde_json::json!({"vm": "microvm-a", "spawn": spawn, "gen": "1", "exit": "0", "end": "eof"}));
    let reconnect = |ts: &str, pid: u32, spawn: &str, reason: &str| row(ts, "agent_reconnect", pid, None, serde_json::json!({"id": "microvm-a", "spawn": spawn, "reason": reason, "ms": "2300"}));
    let probe = end_row(500, "2026-10-20T10:01:00Z", "2026-10-20T10:01:02Z", None, "end:eof; vm:microvm-a; vm_how:started; spawn:sp-0; close_ms:300; pid_rewrite:ok");
    let chat = |vm: &str, drops: u32| end_row(501, "2026-10-20T10:01:00Z", "2026-10-20T10:05:00Z", None, &format!("end:eof; vm:{vm}; vm_how:started; spawn:sp-1; init_ms:9000; close_ms:600; link_drops:{drops}; pid_rewrite:ok"));
    let reopen = |how: &str, init_ms: &str, drops: u32| end_row(502, "2026-10-20T10:20:00Z", "2026-10-20T10:40:00Z", Some(sid), &format!("end:eof; vm:microvm-a; vm_how:{how}; spawn:sp-2; init_ms:{init_ms}; close_ms:700; link_drops:{drops}; pid_rewrite:ok"));
    let census = vec![probe.clone(), chat("microvm-a", 0), reopen("resumed", "4200", 1)];
    let ends = [remote_end("2026-10-20T10:01:02Z", 500, None, "sp-0"), remote_end("2026-10-20T10:05:00Z", 501, Some(sid), "sp-1"), remote_end("2026-10-20T10:40:00Z", 502, Some(sid), "sp-2")];
    let audit = |extra: &[Value]| ends.iter().chain(extra).cloned().collect::<Vec<Value>>();
    let lid = [reconnect("2026-10-20T10:30:00Z", 502, "sp-2", "woke after 181 s asleep")];
    let (close, back, evidence) = reopen_evidence(&census, &audit(&lid), ws, since).unwrap();
    assert_eq!((&close, &back), (&census[1], &census[2]), "the chat's close (never the probe's end row), then its reopen");
    assert_eq!(evidence, format!("session {sid}: closed by wrapper pid 501 on microvm-a (end:eof, close_ms 600), reopened by wrapper pid 502 (vm_how:resumed, init_ms 4200, under 15000); wrapper pid 502 slept (woke after 181 s asleep at \"2026-10-20T10:30:00Z\", spawn sp-2), link_drops 1"));
    assert_closed_well(&close);
    assert_closed_well(&back);
    // The SIGSTOP stand-in's reason, and a sleep in the close's run, pass too.
    let stopped = reopen_evidence(&census, &audit(&[reconnect("2026-10-20T10:31:00Z", 502, "sp-2", "no frame for 190 s")]), ws, since).unwrap().2;
    assert!(stopped.ends_with("wrapper pid 502 slept (no frame for 190 s at \"2026-10-20T10:31:00Z\", spawn sp-2), link_drops 1"), "{stopped}");
    let early = [probe.clone(), chat("microvm-a", 1), reopen("resumed", "4200", 0)];
    let slept_first = reopen_evidence(&early, &audit(&[reconnect("2026-10-20T10:03:00Z", 501, "sp-1", "woke after 200 s asleep")]), ws, since).unwrap().2;
    assert!(slept_first.contains("; wrapper pid 501 slept (woke after 200 s asleep at \"2026-10-20T10:03:00Z\", spawn sp-1), link_drops 1"), "{slept_first}");
    // Each broken link, named.
    let err = |census: &[Value], extra: &[Value]| reopen_evidence(census, &audit(extra), ws, since).unwrap_err();
    assert!(err(&[probe.clone(), chat("microvm-a", 0), reopen("reused", "4200", 1)], &lid).starts_with(&format!("no chat of {FIXTURE_WS} reopened from the picker onto its suspended VM since AI_ENV_CURSOR_SINCE")), "a reused VM: no closing suspend ran");
    assert!(err(&[probe.clone(), chat("microvm-a", 0), reopen("resumed", "15000", 1)], &lid).ends_with(&format!("{sid} (wrapper pid 502) on microvm-a answered initialize after 15000 ms (T10.2: under 15000 ms)")));
    let no_close = format!("no end row of {sid} on microvm-a before its reopen (wrapper pid 502) since AI_ENV_CURSOR_SINCE");
    assert!(err(&[probe.clone(), chat("microvm-b", 0), reopen("resumed", "4200", 1)], &lid).starts_with(&no_close), "the close on another VM");
    assert!(reopen_evidence(&census, &[ends[0].clone(), ends[2].clone(), lid[0].clone()], ws, since).unwrap_err().starts_with(&no_close), "no session_remote_end row names the close's chat");
    assert!(reopen_evidence(&census, &audit(&lid), ws, t("2026-10-20T10:02:00Z")).unwrap_err().starts_with(&no_close), "the close before the step");
    let no_sleep = format!("no agent_reconnect audit row of {sid}'s close (wrapper pid 501) or reopen (wrapper pid 502) after a sleep");
    assert!(err(&census, &[reconnect("2026-10-20T10:30:00Z", 502, "sp-2", "dropped by session drop-transport")]).starts_with(&no_sleep), "a drop's reconnect, not a sleep's");
    assert!(err(&census, &[reconnect("2026-10-20T10:30:00Z", 502, "sp-9", "woke after 181 s asleep")]).starts_with(&no_sleep), "another spawn's");
    assert!(err(&census, &[reconnect("2026-10-20T10:45:00Z", 502, "sp-2", "woke after 181 s asleep")]).starts_with(&no_sleep), "after the run");
    assert!(err(&[probe, chat("microvm-a", 0), reopen("resumed", "4200", 0)], &lid).ends_with(&format!("the run of {sid} that slept (wrapper pid 502) shows link_drops 0: the sleep at \"2026-10-20T10:30:00Z\" lost no link")));
}

/// S10 (T10.3): the re-address's chain, offline. The newest live move off
/// a terminated VM (kind readdress, cause vm_gone, generation 2 or more: a
/// reopen's carry, generation 1, never counts), chained to its wrapper's
/// end row in the workspace, which counts the move and one swallowed init;
/// its `session_move_end` names where it went (under a cut miss's retry's
/// generation too). Each broken link is named.
#[test]
fn readdress_evidence_chains_the_move_to_its_end_row() {
    let t = |ts: &str| ai_env_cli::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
    let (ws, since) = (Path::new(FIXTURE_WS), t("2026-10-20T10:00:00Z"));
    let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let end_row = |cwd: &str, moves: &str, inits: &str| {
        let note = format!("mode:remote; end:eof; vm:microvm-b; vm_how:started; spawn:sp-2; init_ms:9000; {moves}move_ms:41000; cut:at; inits:{inits}; echoes:2/1; close_ms:600; link_drops:0; pid_rewrite:ok");
        serde_json::json!({"pid": 601, "start": t("2026-10-20T10:01:00Z"), "end": t("2026-10-20T10:20:00Z"), "exit": 0, "cwd": cwd, "argv": ["/x/ai-env-claude", "/x/claude"], "note": note})
    };
    let row = |ts: &str, event: &str, pid: u32, detail: Value| serde_json::json!({"v": 1, "ts": ts, "event": event, "session_id": sid, "pid": pid, "detail": detail});
    let moved = |ts: &str, pid: u32, gen: &str, cause: &str| row(ts, "session_move", pid, serde_json::json!({"session": sid, "gen": gen, "kind": "readdress", "cause": cause, "from_vm": "microvm-a", "outstanding": "1", "cancelled": "0"}));
    let went = row("2026-10-20T10:05:41Z", "session_move_end", 601, serde_json::json!({"session": sid, "gen": "2", "kind": "readdress", "outcome": "done", "from_vm": "microvm-a", "to_vm": "microvm-b", "how": "started", "seed": "box", "transcript": "restored", "cut": "at", "touchid": "asked", "ms": "41000"}));
    let counted = "moves:readdress=1,respawn=0,migrate=0; ";
    let census = vec![end_row(FIXTURE_WS, counted, "2/1")];
    // A reopen's carry off a gone VM (generation 1, newer here) is never T10.3's move.
    let audit = vec![moved("2026-10-20T10:05:00Z", 601, "2", "vm_gone"), went, moved("2026-10-20T10:30:00Z", 602, "1", "vm_gone")];
    let (end, evidence) = readdress_evidence(&census, &audit, ws, since).unwrap();
    assert_eq!(end, census[0]);
    assert_eq!(evidence, format!("session {sid}: wrapper pid 601 moved it off microvm-a at \"2026-10-20T10:05:00Z\" (gen 2, readdress, vm_gone; its end: done to microvm-b); the end row on microvm-b: moves:readdress=1,respawn=0,migrate=0, move_ms:41000, cut:at, inits:2/1, echoes:2/1"));
    assert_closed_well(&end);
    assert!(readdress_evidence(&census, &audit[..1], ws, since).unwrap().1.contains("(gen 2, readdress, vm_gone; its end: -)"), "its end not written yet");
    // A cut miss's retry writes the move's one end row under its own generation (gen 3 for the gen 2 move).
    let mut retried = audit.clone();
    retried[1]["detail"]["gen"] = serde_json::json!("3");
    assert!(readdress_evidence(&census, &retried, ws, since).unwrap().1.contains("(gen 2, readdress, vm_gone; its end: done to microvm-b)"), "the retry's end row");
    // Each broken link, named.
    let err = |census: &[Value], audit: &[Value], since: u64| readdress_evidence(census, audit, ws, since).unwrap_err();
    let none = "no session_move audit row of kind readdress whose cause is vm_gone (a live move, generation 2 or more";
    assert!(err(&census, &[moved("2026-10-20T10:05:00Z", 601, "2", "unreachable")], since).starts_with(none), "an unreachable VM's move");
    assert!(err(&census, &audit, t("2026-10-20T10:06:00Z")).starts_with(none), "before the step");
    assert!(err(&census, &audit[2..], since).starts_with(none), "a reopen's carry alone");
    assert!(err(&[], &audit, since).starts_with("no census end row of wrapper pid 601 whose run holds its move at \"2026-10-20T10:05:00Z\""));
    assert!(err(&[end_row("/Users/mike/Documents/DeFi/ai-env", counted, "2/1")], &audit, since).contains(&format!("not in {FIXTURE_WS} (AI_ENV_CURSOR_WORKSPACE)")), "the development checkout");
    assert!(err(&[end_row(FIXTURE_WS, "", "2/1")], &audit, since).contains("shows moves:- where the re-address counts"));
    assert!(err(&[end_row(FIXTURE_WS, "moves:readdress=0,respawn=1,migrate=0; ", "2/1")], &audit, since).contains("shows moves:readdress=0,respawn=1,migrate=0 where"));
    assert!(err(&[end_row(FIXTURE_WS, counted, "2/0")], &audit, since).contains("shows inits:2/0 where the moved generation's init, swallowed once, reads inits:<n>/1"));
    // The parts' readers.
    let note = |n: &str| serde_json::json!({"note": format!("mode:remote; {n}")});
    assert_eq!(moves(&note("moves:readdress=2,respawn=1,migrate=0")), Some([2, 1, 0]));
    assert_eq!((moves(&note("moves:readdress=1,teleport=1")), moves(&note("end:eof"))), (None, None), "an unknown kind; no part");
    assert_eq!((forwarded_swallowed(&note("inits:3/1"), "inits"), forwarded_swallowed(&note("inits:3"), "inits")), (Some((3, 1)), None));
}

/// S10 (T10.4): the migration's chain, offline. (a) A wall migration done
/// (phase B's `session_move` and its end; phase A's row before it is the
/// live generation's), its wrapper's end row counting it, the old VM's row
/// terminated by migrate, the new VM seeded with a WIP by this move (seed
/// box, seeded in or after its start's second); else (b) a reopen's carry
/// (`carried:`). Each broken link of (a) is named, with (b)'s absence: a
/// reused VM's earlier seed and a kept or Mac seed among them.
#[test]
fn migration_evidence_takes_a_wall_migration_or_a_reopens_carry() {
    let t = |ts: &str| ai_env_cli::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
    let (ws, since) = (Path::new(FIXTURE_WS), t("2026-10-20T10:00:00Z"));
    let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let end_row = |moves: &str| {
        let note = format!("mode:remote; end:eof; vm:microvm-b; vm_how:started; spawn:sp-2; init_ms:9000; moves:{moves}; move_ms:30000; cut:none; inits:3/0; echoes:3/0; close_ms:600; link_drops:0; pid_rewrite:ok");
        serde_json::json!({"pid": 701, "start": t("2026-10-20T10:00:00Z"), "end": t("2026-10-20T10:30:00Z"), "exit": 0, "cwd": FIXTURE_WS, "argv": ["/x/ai-env-claude", "/x/claude"], "note": note})
    };
    let row = |ts: &str, event: &str, detail: Value| serde_json::json!({"v": 1, "ts": ts, "event": event, "session_id": sid, "pid": 701, "detail": detail});
    let started = |ts: &str, gen: &str, trigger: &str| row(ts, "session_move", serde_json::json!({"session": sid, "gen": gen, "kind": "migrate", "trigger": trigger, "from_vm": "microvm-a", "outstanding": "0", "cancelled": "0"}));
    let ended = |outcome: &str| {
        row("2026-10-20T10:12:30Z", "session_move_end", serde_json::json!({"session": sid, "gen": "2", "kind": "migrate", "outcome": outcome, "from_vm": "microvm-a", "to_vm": "microvm-b", "how": "started", "seed": "box", "transcript": "restored", "cut": "none", "touchid": "asked", "ms": "30000"}))
    };
    let audit = |trigger: &str, outcome: &str| vec![started("2026-10-20T10:10:00Z", "1", trigger), started("2026-10-20T10:12:00Z", "2", trigger), ended(outcome)];
    let vm_row = |by: &str| serde_json::json!({"id": "microvm-a", "status": "terminated", "terminated_by": by, "leaving_for": "microvm-b"});
    // `seeded_at` in Unix seconds, as `rows::record_seed` writes it; phase B's seed follows its `session_move` (10:12:00).
    let ws_row = |at: &str, wip: Option<&str>| serde_json::json!({"root": FIXTURE_WS, "vm": {"microvm-b": {"seeded_at": t(at) / 1000, "mode": "clone", "seeded_wip": wip}}});
    let seeded = |wip: Option<&str>| ws_row("2026-10-20T10:12:10Z", wip);
    let census = vec![end_row("readdress=0,respawn=0,migrate=1")];
    let vms = [vm_row("migrate"), serde_json::json!({"id": "microvm-b", "status": "running", "terminated_by": null})];
    let wip = "c0ffee0000000000000000000000000000000001";
    let (end, evidence) = migration_evidence(&census, &audit("wall", "done"), &vms, &[seeded(Some(wip))], ws, since).unwrap();
    assert_eq!(end, census[0]);
    assert_eq!(evidence, format!("a wall migration: wrapper pid 701 moved session {sid} off microvm-a to microvm-b at \"2026-10-20T10:12:30Z\" (gen 2, how started, seed box, transcript restored); microvm-a terminated by migrate (leaving_for microvm-b); microvm-b seeded with the WIP {wip}; the end row: moves:readdress=0,respawn=0,migrate=1"));
    assert_closed_well(&end);
    assert!(migration_evidence(&census, &audit("wall", "done"), &vms, &[ws_row("2026-10-20T10:12:00Z", Some(wip))], ws, since).is_ok(), "a seed in the move's own second");
    // Each broken link of (a), named, when no reopen carried a chat.
    let err = |census: &[Value], audit: &[Value], vms: &[Value], wip: Option<&str>| migration_evidence(census, audit, vms, &[seeded(wip)], ws, since).unwrap_err();
    let nor = format!("; nor did a reopen carry a chat off its VM in {FIXTURE_WS} since AI_ENV_CURSOR_SINCE (an end row with --resume and carried:migrate, near the wall, or carried:readdress, past it)");
    let why = err(&census, &audit("wall", "done"), &[vm_row("platform")], Some(wip));
    assert!(why.starts_with("the old VM microvm-a's row says terminated_by platform (status \"terminated\")") && why.ends_with(&nor), "{why}");
    assert!(err(&census, &audit("wall", "done"), &[], Some(wip)).starts_with("the old VM microvm-a has no row in state/vms"));
    let no_wip = "no workspace row records the new VM microvm-b seeded with a WIP snapshot at or after the migration's start at \"2026-10-20T10:12:00Z\" (seeded_wip, seeded_at)";
    assert!(err(&census, &audit("wall", "done"), &vms, None).starts_with(no_wip));
    let stale = migration_evidence(&census, &audit("wall", "done"), &vms, &[ws_row("2026-10-20T10:05:00Z", Some(wip))], ws, since).unwrap_err();
    assert!(stale.starts_with(no_wip), "a reused VM an earlier chat seeded before the move: {stale}");
    for seed in ["kept", "mac"] {
        let mut other = audit("wall", "done");
        other[2]["detail"]["seed"] = serde_json::json!(seed);
        let why = err(&census, &other, &vms, Some(wip));
        assert!(why.starts_with(&format!("the migration of wrapper pid 701 seeded microvm-b from {seed}, not from microvm-a's last fetch (seed box)")), "{why}");
        assert!(why.contains(if seed == "kept" { "(occupied): terminate the workspace's other suspended VMs" } else { "(seed box): leave an uncommitted edit" }), "{why}");
    }
    assert!(err(&census, &audit("command", "done"), &vms, Some(wip)).starts_with("the migration of wrapper pid 701 off microvm-a at \"2026-10-20T10:12:00Z\" was triggered by command, not the wall"), "session migrate's");
    assert!(err(&census, &audit("wall", "stayed"), &vms, Some(wip)).starts_with("no migration done since AI_ENV_CURSOR_SINCE"), "phase B's fallback to the old VM");
    assert!(err(&census, &audit("wall", "done")[2..], &vms, Some(wip)).starts_with("the migration of wrapper pid 701 off microvm-a (gen 2) has no session_move row before its end at \"2026-10-20T10:12:30Z\""));
    assert!(err(&[], &audit("wall", "done"), &vms, Some(wip)).starts_with("no census end row of wrapper pid 701 whose run holds its migration at \"2026-10-20T10:12:00Z\""));
    assert!(err(&[end_row("readdress=1,respawn=0,migrate=0")], &audit("wall", "done"), &vms, Some(wip)).starts_with("the end row of wrapper pid 701 shows moves:readdress=1,respawn=0,migrate=0 where the migration counts"));
    // (b): a reopen's carry, whatever (a) lacks.
    let carry = serde_json::json!({"pid": 702, "start": t("2026-10-20T10:40:00Z"), "end": t("2026-10-20T10:50:00Z"), "exit": 0, "cwd": FIXTURE_WS, "argv": ["/x/ai-env-claude", "/x/claude", "--resume", sid], "note": "mode:remote; end:eof; vm:microvm-c; vm_how:started; seed:seeded; transcript:restored; spawn:sp-3; init_ms:21000; moves:readdress=0,respawn=0,migrate=1; close_ms:600; carried:migrate; pid_rewrite:ok"});
    let (end, evidence) = migration_evidence(&[census[0].clone(), carry.clone()], &audit("wall", "done"), &[vm_row("platform")], &[], ws, since).unwrap();
    assert_eq!(end, carry);
    assert_eq!(evidence, format!("a reopen's carry: session {sid} reopened by wrapper pid 702 carried:migrate onto microvm-c (vm_how:started, seed:seeded, transcript:restored, moves:readdress=0,respawn=0,migrate=1)"));
    assert_closed_well(&end);
}

/// S10 (T10.5): the park's chain, offline, in the audit's order. A park
/// at a prompt and its unpark by the answer, then a move done, then a
/// subtree pull into the new VM by that wrapper beyond the main
/// transcript's restore (before or after the move's end row: they race).
/// The move's end row is the wrapper's first after it, whatever its
/// generation (a cut miss's retry's). Each broken link is named: no
/// subtree pull (the main one alone, another wrapper's, another VM's, a
/// missing transcript word counting the main one), an idle park, an unpark
/// by a user line or after the move, a failed move, no move end, no move
/// since the step, no end row.
#[test]
fn park_evidence_chains_the_park_the_move_and_the_subtree_pull() {
    let t = |ts: &str| ai_env_cli::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
    let (ws, since) = (Path::new(FIXTURE_WS), t("2026-10-20T10:00:00Z"));
    let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let note = "mode:remote; end:eof; vm:microvm-b; vm_how:started; spawn:sp-2; init_ms:9000; moves:readdress=1,respawn=0,migrate=0; move_ms:41000; cut:none; inits:3/0; echoes:3/0; close_ms:600; link_drops:0; park:1; parked_s:610; unpark_ms:2400; unpark_resumed:1; pid_rewrite:ok";
    let census = vec![serde_json::json!({"pid": 801, "start": t("2026-10-20T10:00:00Z"), "end": t("2026-10-20T10:40:00Z"), "exit": 0, "cwd": FIXTURE_WS, "argv": ["/x/ai-env-claude", "/x/claude"], "note": note})];
    let row = |ts: &str, event: &str, pid: u32, detail: Value| serde_json::json!({"v": 1, "ts": ts, "event": event, "session_id": null, "pid": pid, "detail": detail});
    let park = |why: &str| row("2026-10-20T10:05:00Z", "session_park", 801, serde_json::json!({"vm": "microvm-a", "spawn": "sp-1", "why": why, "quiet_ms": "300000"}));
    let unpark = |ts: &str, by: &str| row(ts, "session_unpark", 801, serde_json::json!({"vm": "microvm-a", "spawn": "sp-1", "by": by, "vm_state": "suspended", "ms": "2400"}));
    let answered = || unpark("2026-10-20T10:15:00Z", "control_response");
    let moved = row("2026-10-20T10:20:00Z", "session_move", 801, serde_json::json!({"session": sid, "gen": "2", "kind": "readdress", "cause": "vm_gone", "from_vm": "microvm-a", "outstanding": "1", "cancelled": "0"}));
    let went = |outcome: &str, transcript: &str| {
        row("2026-10-20T10:20:30Z", "session_move_end", 801, serde_json::json!({"session": sid, "gen": "2", "kind": "readdress", "outcome": outcome, "from_vm": "microvm-a", "to_vm": "microvm-b", "how": "started", "seed": "box", "transcript": transcript, "cut": "none", "touchid": "asked", "ms": "30000"}))
    };
    let pull = |ts: &str, pid: u32, vm: &str| row(ts, "transcript_pull", pid, serde_json::json!({"session": sid, "vm": vm, "parts": "1", "bytes": "2048", "outcome": "written", "ms": "300"}));
    // The main transcript's restore (M2, before the spawn), then a subagent's file (after the spawn).
    let (main, sub) = (pull("2026-10-20T10:20:20Z", 801, "microvm-b"), pull("2026-10-20T10:20:31Z", 801, "microvm-b"));
    let chain = |park: Value, unpark: Value, went: Value, after: &[Value]| -> Vec<Value> { [park, unpark, moved.clone(), main.clone(), went].into_iter().chain(after.iter().cloned()).collect() };
    let audit = chain(park("prompt"), answered(), went("done", "restored"), std::slice::from_ref(&sub));
    let (end, evidence) = park_evidence(&census, &audit, ws, since).unwrap();
    assert_eq!(end, census[0]);
    assert_eq!(evidence, format!("session {sid}: wrapper pid 801 parked spawn sp-1 on microvm-a at a prompt at \"2026-10-20T10:05:00Z\" (quiet_ms 300000), unparked by the answer at \"2026-10-20T10:15:00Z\" (vm_state suspended, 2400 ms); moved off microvm-a to microvm-b at \"2026-10-20T10:20:00Z\" (readdress, gen 2); 1 subtree pull(s) into microvm-b beside the main transcript's 1; the end row: park:1, unpark_resumed:1, moves:readdress=1,respawn=0,migrate=0"));
    assert_closed_well(&end);
    // The subtree's pull races the move's end row; a move whose transcript the new VM kept restores no main one.
    assert!(park_evidence(&census, &[park("prompt"), answered(), moved.clone(), main.clone(), sub.clone(), went("done", "restored")], ws, since).is_ok());
    let kept = park_evidence(&census, &chain(park("prompt"), answered(), went("done", "kept"), &[]), ws, since).unwrap().1;
    assert!(kept.contains("; 1 subtree pull(s) into microvm-b beside the main transcript's 0;"), "{kept}");
    // A cut miss's retry writes the move's one done row under its own generation (gen 3 for the gen 2 move).
    let mut retried = went("done", "restored");
    retried["detail"]["gen"] = serde_json::json!("3");
    assert!(park_evidence(&census, &chain(park("prompt"), answered(), retried, std::slice::from_ref(&sub)), ws, since).is_ok(), "the retry's done row");
    // Each broken link, named.
    let err = |audit: &[Value]| park_evidence(&census, audit, ws, since).unwrap_err();
    let no_subtree = format!("no subtree pull into microvm-b after the move of wrapper pid 801 at \"2026-10-20T10:20:00Z\": 1 transcript_pull row(s) of {sid} written there, the main transcript's 1 (transcript:restored)");
    assert!(err(&chain(park("prompt"), answered(), went("done", "restored"), &[])).starts_with(&no_subtree), "the main transcript's restore alone");
    assert!(err(&chain(park("prompt"), answered(), went("done", "restored"), &[pull("2026-10-20T10:25:00Z", 802, "microvm-b")])).starts_with(&no_subtree), "another wrapper's pull (a reopen's)");
    assert!(err(&chain(park("prompt"), answered(), went("done", "restored"), &[pull("2026-10-20T10:25:00Z", 801, "microvm-a")])).starts_with(&no_subtree), "a pull into another VM");
    let mut unworded = went("done", "restored");
    unworded["detail"].as_object_mut().unwrap().remove("transcript");
    let why = err(&chain(park("prompt"), answered(), unworded, &[]));
    assert!(why.ends_with(&format!("1 transcript_pull row(s) of {sid} written there, the main transcript's 1 (transcript:-): run a Task-tool turn and wait for its sync before the terminate")), "a missing word counts the main restore: {why}");
    let no_prompt = "wrapper pid 801 parked at no prompt before its move at \"2026-10-20T10:20:00Z\" (a session_park row with why prompt, then that spawn's session_unpark by control_response, the answer)";
    assert!(err(&chain(park("idle"), answered(), went("done", "restored"), std::slice::from_ref(&sub))).starts_with(no_prompt), "an idle park");
    assert!(err(&chain(park("prompt"), unpark("2026-10-20T10:15:00Z", "user"), went("done", "restored"), std::slice::from_ref(&sub))).starts_with(no_prompt), "unparked by a user line");
    assert!(err(&[park("prompt"), moved.clone(), unpark("2026-10-20T10:21:00Z", "control_response"), main.clone(), went("done", "restored"), sub.clone()]).starts_with(no_prompt), "the answer after the move");
    assert!(err(&chain(park("prompt"), answered(), went("failed", "restored"), std::slice::from_ref(&sub))).starts_with("the move of wrapper pid 801 at \"2026-10-20T10:20:00Z\" (gen 2) ended failed, not done"));
    assert!(err(&[park("prompt"), answered(), moved.clone(), main.clone(), sub.clone()]).ends_with("(gen 2) has no session_move_end row: its claude never started on the new VM"));
    assert!(park_evidence(&census, &audit, ws, t("2026-10-20T10:30:00Z")).unwrap_err().starts_with("no session_move audit row since AI_ENV_CURSOR_SINCE"));
    assert!(park_evidence(&[], &audit, ws, since).unwrap_err().starts_with("no census end row of wrapper pid 801 whose run holds its move at \"2026-10-20T10:20:00Z\""));
}

/// S10 (F11): the placeholder's reopen, offline. A new chat's first run
/// (its chat named by its wrapper's `session_remote_end` row) closed before
/// any `transcript_push` of it (the reopen's sync comes after), then its
/// reopen from the picker kept on that VM, not carried off it. Each broken
/// link is named: a push before the close, another VM, a run naming no VM,
/// no row naming the first run's chat, a restore instead of a kept
/// transcript, a carry.
#[test]
fn placeholder_evidence_chains_the_unsynced_close_to_the_kept_reopen() {
    let t = |ts: &str| ai_env_cli::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
    let (ws, since) = (Path::new(FIXTURE_WS), t("2026-10-20T10:00:00Z"));
    let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let end_row = |pid: u32, start: &str, end: &str, resume: bool, note: &str| {
        let argv: Vec<&str> = ["/x/ai-env-claude", "/x/claude"].into_iter().chain(resume.then_some(["--resume", sid]).into_iter().flatten()).collect();
        serde_json::json!({"pid": pid, "start": t(start), "end": t(end), "exit": 0, "cwd": FIXTURE_WS, "argv": argv, "note": format!("mode:remote; {note}")})
    };
    // Closed during its first turn (S9 B6 (j): end:eof_kill), then reopened on its VM.
    let first = |vm: &str| end_row(901, "2026-10-20T10:01:00Z", "2026-10-20T10:02:30Z", false, &format!("end:eof_kill; vm:{vm}; vm_how:started; spawn:sp-1; init_ms:9000; close_ms:1261; link_drops:0; pid_rewrite:ok"));
    let reopen = |transcript: &str, carried: &str| end_row(902, "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z", true, &format!("end:eof; vm:microvm-a; vm_how:reused; transcript:{transcript}; spawn:sp-2; init_ms:3000; close_ms:600; link_drops:0; {carried}pid_rewrite:ok"));
    let row = |ts: &str, event: &str, pid: u32, session: Option<&str>, detail: Value| serde_json::json!({"v": 1, "ts": ts, "event": event, "session_id": session, "pid": pid, "detail": detail});
    let named = row("2026-10-20T10:02:30Z", "session_remote_end", 901, Some(sid), serde_json::json!({"vm": "microvm-a", "spawn": "sp-1", "gen": "1", "exit": "0", "end": "eof_kill"}));
    let push = |ts: &str, pid: u32| row(ts, "transcript_push", pid, None, serde_json::json!({"session": sid, "vm": "microvm-a", "kind": "main", "from": "0", "len": "4096", "s3_status": "200", "ms": "200"}));
    let census = vec![first("microvm-a"), reopen("kept", "")];
    let audit = vec![named.clone(), push("2026-10-20T10:06:00Z", 902)];
    let (began, back, evidence) = placeholder_evidence(&census, &audit, ws, since).unwrap();
    assert_eq!((&began, &back), (&census[0], &census[1]));
    assert_eq!(evidence, format!("session {sid}: a new chat (wrapper pid 901) on microvm-a closed before any transcript_push of it (end:eof_kill, close_ms 1261), then reopened from the picker by wrapper pid 902 on microvm-a (vm_how:reused, transcript:kept, init_ms 3000)"));
    assert_closed_well(&back);
    // Each broken link, named.
    let err = |census: &[Value], audit: &[Value]| placeholder_evidence(census, audit, ws, since).unwrap_err();
    assert!(err(&census, &[named.clone(), push("2026-10-20T10:02:00Z", 901)]).starts_with(&format!("{sid}'s first run (wrapper pid 901) synced before it closed (transcript_push at \"2026-10-20T10:02:00Z\")")));
    assert!(err(&[first("microvm-b"), reopen("kept", "")], &audit).starts_with(&format!("{sid} began on microvm-b (wrapper pid 901) and was reopened on microvm-a")));
    // Two runs naming no VM never match on the missing part.
    let unplaced = end_row(901, "2026-10-20T10:01:00Z", "2026-10-20T10:02:30Z", false, "end:eof_kill; spawn:sp-1; close_ms:1261; link_drops:0; pid_rewrite:ok");
    let reopened_nowhere = end_row(902, "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z", true, "end:eof; transcript:kept; close_ms:600; pid_rewrite:ok");
    assert_eq!(err(&[unplaced.clone(), reopened_nowhere], &audit), format!("{sid} was reopened kept (wrapper pid 902) but its end row names no VM"));
    assert!(err(&[unplaced, reopen("kept", "")], &audit).starts_with(&format!("{sid} began on - (wrapper pid 901) and was reopened on microvm-a")), "the first run names no VM");
    assert!(err(&census, &audit[1..]).starts_with(&format!("{sid} was reopened kept on microvm-a (wrapper pid 902), but no new chat's end row before it served it")), "no session_remote_end row names the first run's chat");
    let none = format!("no chat of {FIXTURE_WS} reopened from the picker with its transcript kept on its VM since AI_ENV_CURSOR_SINCE");
    assert!(err(&[first("microvm-a"), reopen("restored", "")], &audit).starts_with(&none), "restored into a new VM");
    assert!(err(&[first("microvm-a"), reopen("kept", "carried:migrate; ")], &audit).starts_with(&none), "carried off a VM near its wall");
}
