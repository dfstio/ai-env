//! The S7 probes of this Mac alone (`Source::Mac`): `touchid-gui` and
//! `oauth-t1`. No VM, no AWS call, no runtime key: `lab run` reaches them
//! before any backend. (`setup-token-prefix` is recorded by `ai-env creds
//! setup-token` itself.)
//!
//! - **touchid-gui** (G8): does age-plugin-se show its Touch ID dialog to
//!   processes Cursor started? It must run in Cursor's integrated terminal
//!   (the process ancestry is checked). It seals a throwaway value to the
//!   `[creds].key` recipients (no prompt), unseals it in the terminal, then
//!   from a detached child in its own session with no terminal — the shape of
//!   S8's prewarm. `prompted` when both answered, `terminal-only` when only
//!   the terminal did, `failed:<why>` otherwise.
//! - **oauth-t1**: the real CLI's OAuth refresh, in stream-json host mode
//!   with the extension's entrypoint (`CLAUDE_CODE_ENTRYPOINT=claude-vscode`,
//!   S1's `entrypoint` probe) and `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1`,
//!   which the stock extension never sets (Tier B adds it), and a token
//!   Anthropic refuses — the CLI asks its host for a refresh only with
//!   both ([`ENTRYPOINT`]): when it asks (`oauth_token_refresh`), what no
//!   reply, a null reply and (with the sealed token, one Touch ID) a valid
//!   reply do, how long each takes, and whether
//!   `CLAUDE_CODE_OAUTH_401_WAIT_MS` is honoured (a null reply with it set:
//!   the result comes at least that much later). With no reply the CLI's
//!   stdin stays open after its result, so an exit would be its own: none is
//!   expected, and that run ends at its 150 s bound, since
//!   `CLAUDE_CODE_AUTH_FAIL_EXIT_MS` acts only for a remote child
//!   (`CLAUDE_CODE_REMOTE_SESSION_ID` set), which ai-env's CLI never is (so
//!   it is not set). A seal `vm exec` would refuse
//!   to unseal (Anthropic already refused it: `state/creds.toml`) is never
//!   unsealed or sent: the valid reply is then skipped, loudly, as it is when
//!   none of the first three runs asked for a refresh (it could never be
//!   sent: no Touch ID for it). It makes real requests to Anthropic; every
//!   run has an empty config dir and HOME of its own. The closing encodes
//!   `authwatch::AUTH_TIMERS` from its row.
use crate::age_cmd::{effective_path, AgeTool};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::errors::{CliError, Result};
use crate::store::{validate_key_name, Keystore};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A verdict and its note.
pub type MacOutcome = (String, String);

// ---- touchid-gui ---------------------------------------------------------------------------

/// The first ancestor (from this process up) whose command names Cursor:
/// `ps` answers (parent pid, command) for a pid. At most 32 steps.
pub fn cursor_ancestor(ps: &dyn Fn(u32) -> Option<(u32, String)>, start: u32) -> Option<String> {
    let mut pid = start;
    for _ in 0..32 {
        let (ppid, comm) = ps(pid)?;
        if comm.contains("Cursor") {
            return Some(comm);
        }
        if ppid <= 1 || ppid == pid {
            return None;
        }
        pid = ppid;
    }
    None
}

/// `/bin/ps -o ppid= -o comm= -p PID`.
fn ps(pid: u32) -> Option<(u32, String)> {
    let out = Command::new("/bin/ps").args(["-o", "ppid=", "-o", "comm=", "-p", &pid.to_string()]).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.trim();
    let (ppid, comm) = line.split_once(char::is_whitespace)?;
    Some((ppid.trim().parse().ok()?, comm.trim().to_string()))
}

/// The first line of an error, cut to a verdict-sized word list.
fn short(e: &str) -> String {
    e.lines().next().unwrap_or_default().chars().filter(|c| !c.is_control()).take(80).collect::<String>().replace(' ', "-")
}

/// `lab run touchid-gui` (see the module doc).
pub fn touchid_gui(store: &Keystore, cfg: &BridgeConfig) -> Result<MacOutcome> {
    let Some(cursor) = cursor_ancestor(&ps, std::process::id()) else {
        return Err(CliError::Usage("touchid-gui runs from Cursor's integrated terminal (no Cursor among this command's ancestors): open a terminal in Cursor and run it there".into()));
    };
    let key = cfg.creds.key.as_str();
    validate_key_name(key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    if !store.key_exists(key) {
        return Err(CliError::AuthUnavailable(format!("keystore key {key:?} does not exist: ai-env keygen {key}")));
    }
    let age = AgeTool::probe()?;
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let marker = format!("touchid-gui-throwaway-{nanos}");
    let ciphertext = age.encrypt(&store.recipients_path(key), marker.as_bytes())?;
    let identity = store.identity_path(key);
    let budget = Duration::from_secs(cfg.creds.unseal_timeout_s);
    eprintln!("ai-env: touchid-gui: 1/2 an unseal in this terminal (from {cursor}): answer the Touch ID dialog");
    // The classic decrypt: its age stays in this terminal's foreground group, so a Ctrl-C ends the dialog too
    // (an `UnsealJob`'s age has a group of its own and would outlive this process).
    let t = Instant::now();
    let terminal = age.decrypt_to_bytes(&identity, &ciphertext);
    let terminal_ms = t.elapsed().as_millis();
    match terminal {
        Ok(p) if p.as_slice() == marker.as_bytes() => {}
        Ok(_) => return Ok(("failed:terminal-mismatch".into(), format!("from {cursor}: the terminal unseal returned another value ({terminal_ms} ms)"))),
        Err(e) => return Ok((format!("failed:terminal:{}", short(&e.to_string())), format!("from {cursor}: the terminal unseal failed after {terminal_ms} ms"))),
    }
    eprintln!("ai-env: touchid-gui: 2/2 the same unseal from a detached process with no terminal (S8's prewarm): answer the dialog if it appears");
    let (detached_ok, detached_ms, why) = detached_unseal(&age, &identity, &ciphertext, marker.as_bytes(), budget)?;
    let verdict = crate::bridge::probes::verdict_touchid_gui(detached_ok).to_string();
    let note = format!("from {cursor}; terminal {terminal_ms} ms; detached {detached_ms} ms{}", why.map(|w| format!(" ({w})")).unwrap_or_default());
    Ok((verdict, note))
}

/// `age -d` in a new session with stdio away from any terminal, its
/// ciphertext and plaintext in private files: (answered with `want`, ms, why
/// not). Bounded by `budget`; the whole group is killed past it.
fn detached_unseal(age: &AgeTool, identity: &Path, ciphertext: &[u8], want: &[u8], budget: Duration) -> Result<(bool, u128, Option<String>)> {
    let dir = tempfile::Builder::new().prefix("touchid-gui-").tempdir_in(std::env::temp_dir()).map_err(|e| CliError::Msg(format!("a private temp dir: {e}")))?;
    let (input, output, err) = (dir.path().join("in.age"), dir.path().join("out"), dir.path().join("err"));
    std::fs::write(&input, ciphertext)?;
    let err_file = std::fs::File::create(&err)?;
    let mut cmd = detached_cmd(age.age_path(), identity, &output, &input);
    cmd.stderr(err_file);
    let t = Instant::now();
    let mut child = cmd.spawn().map_err(|e| CliError::Msg(format!("{}: {e}", age.age_path().display())))?;
    let pid = i32::try_from(child.id()).unwrap_or(0);
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if t.elapsed() > budget {
            // SAFETY: killpg on the group this child leads (setsid made it a leader).
            unsafe {
                libc::killpg(pid, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(500));
            // SAFETY: as above.
            unsafe {
                libc::killpg(pid, libc::SIGKILL);
            }
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let ms = t.elapsed().as_millis();
    let got = std::fs::read(&output).unwrap_or_default();
    let stderr = std::fs::read_to_string(&err).unwrap_or_default();
    Ok(match status {
        Some(s) if s.success() && got == want => (true, ms, None),
        Some(s) if s.success() => (false, ms, Some("another value came back".into())),
        Some(s) => (false, ms, Some(format!("exit {:?}: {}", s.code(), short(&stderr)))),
        None => (false, ms, Some(format!("no answer within {} s", budget.as_secs()))),
    })
}

/// The detached `age -d -i identity -o output input` of [`detached_unseal`]:
/// its own session (`setsid`), no terminal on stdin or stdout, PATH as every
/// age call has it, and, as `age_cmd` starts every age and age-keygen, none
/// of `CHILD_ENV_REMOVED`: a `lab run` started with a token or a key in its
/// environment never hands it to age, its plugin or the dialog it shows.
fn detached_cmd(age: &Path, identity: &Path, output: &Path, input: &Path) -> Command {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = Command::new(age);
    cmd.arg("-d").arg("-i").arg(identity).arg("-o").arg(output).arg(input).env("PATH", effective_path()).stdin(Stdio::null()).stdout(Stdio::null());
    for name in crate::age_cmd::CHILD_ENV_REMOVED {
        cmd.env_remove(name);
    }
    // SAFETY: setsid() is async-signal-safe and touches no memory of the parent.
    unsafe {
        cmd.pre_exec(|| if libc::setsid() == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) });
    }
    cmd
}

// ---- oauth-t1 ------------------------------------------------------------------------------

/// How the harness answers the CLI's `oauth_token_refresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Never answered.
    None,
    /// `{"accessToken":null}`.
    Null,
    /// The sealed token.
    Valid,
}

/// One run's observations (milliseconds from the user message).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    /// When the CLI asked for a refresh.
    pub refresh_ms: Option<u128>,
    /// The result: (is_error, subtype), and when.
    pub result: Option<(bool, String)>,
    pub result_ms: Option<u128>,
    /// When the CLI exited, and its code.
    pub exit_ms: Option<u128>,
    pub exit_code: Option<i32>,
    /// When the harness closed the CLI's stdin (after the result of a run
    /// that replied): an exit after it may be the close's doing, not the CLI's own.
    pub closed_ms: Option<u128>,
    /// The run hit the harness's bound.
    pub timed_out: bool,
}

impl Observed {
    /// One note field: `refresh@<ms> result=<subtype|is_error>@<ms> exit=<code>@<ms>`,
    /// then ` stdin-closed@<ms>` when the harness closed stdin.
    #[must_use]
    pub fn describe(&self) -> String {
        let at = |m: Option<u128>| m.map_or_else(|| "-".to_string(), |m| m.to_string());
        let result = self.result.as_ref().map_or_else(|| "none".to_string(), |(e, s)| format!("{}{}", s, if *e { "/is_error" } else { "" }));
        let closed = self.closed_ms.map_or_else(String::new, |m| format!(" stdin-closed@{m}"));
        format!("refresh@{} result={result}@{} exit={}@{}{closed}{}", at(self.refresh_ms), at(self.result_ms), self.exit_code.map_or_else(|| "-".to_string(), |c| c.to_string()), at(self.exit_ms), if self.timed_out { " TIMEOUT" } else { "" })
    }
}

/// What one stdout line tells the harness: a refresh request (its id), a
/// result (is_error, subtype), or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Refresh(String),
    Result(bool, String),
    Other,
}

#[must_use]
pub fn classify(line: &str) -> Seen {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { return Seen::Other };
    let s = |v: &serde_json::Value, k: &str| v.get(k).and_then(serde_json::Value::as_str).map(str::to_string);
    match s(&v, "type").as_deref() {
        Some("control_request") => {
            let sub = v.get("request").and_then(|r| s(r, "subtype"));
            match (sub.as_deref(), s(&v, "request_id")) {
                (Some("oauth_token_refresh"), Some(id)) => Seen::Refresh(id),
                _ => Seen::Other,
            }
        }
        Some("result") => Seen::Result(v.get("is_error").and_then(serde_json::Value::as_bool).unwrap_or(false), s(&v, "subtype").unwrap_or_default()),
        _ => Seen::Other,
    }
}

/// The refused token every run starts with (a setup-token's shape, built
/// at run time; Anthropic answers it 401).
fn refused_token() -> String {
    format!("sk-ant-oat01-{}", "Xq3_".repeat(24))
}

/// The entrypoint every run has, beside `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1`:
/// the one the extension sets (S1's `entrypoint` probe), which `[wrapper]
/// env_forward` carries to the VM. The CLI asks its host for a refresh only
/// when that variable is set and its entrypoint is `claude-desktop`,
/// `local-agent` or `claude-vscode` (2.1.288's `SDK_OAUTH_REFRESH_ENTRYPOINTS`);
/// without one it takes `cli` or `sdk-cli` and never asks, so no reply would
/// ever be sent and the row would read `no-refresh-request` whatever the CLI
/// does under Cursor.
const ENTRYPOINT: &str = "claude-vscode";

/// `CLAUDE_CODE_OAUTH_401_WAIT_MS` for the knob run: once the host's refresh
/// failed (here a null reply), the CLI waits this long for a rotated token in
/// its environment before it gives up — for any child (its default is 0
/// outside a remote session) — so, honoured, that run's result comes at
/// least this much after the null run's.
const WAIT_401_MS: &str = "5000";

/// How long the harness keeps reading once the CLI exited (or was killed):
/// what it wrote just before, or what a child of it still holding its stdout
/// writes, until the pipe's end or this long. The exit is seen first, so a
/// line still queued then would otherwise be lost (a result read as none).
const DRAIN: Duration = Duration::from_secs(2);

/// Write one line to the CLI's stdin while it is open (a CLI that is gone is
/// no error here).
fn send_line(w: &mut Option<std::process::ChildStdin>, line: &str) {
    if let Some(w) = w {
        let _ = w.write_all(line.as_bytes()).and_then(|()| w.write_all(b"\n")).and_then(|()| w.flush());
    }
}

/// One stdout line of the CLI, read at `at` (`t`: the user message): a
/// refresh request is timed and answered on `stdin` per `reply`; the first
/// result is timed and ends the turn by closing stdin, unless no reply is
/// given: then stdin stays open, so an exit timed is the CLI's own, not the
/// close's doing (none is expected: `CLAUDE_CODE_AUTH_FAIL_EXIT_MS` acts only
/// for a remote child, so such a run ends at its bound).
fn observe(seen: &mut Observed, stdin: &mut Option<std::process::ChildStdin>, line: &str, at: Instant, t: Instant, reply: Reply, valid: Option<&str>) {
    let ms = at.saturating_duration_since(t).as_millis();
    match classify(line) {
        Seen::Refresh(id) => {
            seen.refresh_ms.get_or_insert(ms);
            let answer = match reply {
                Reply::None => None,
                Reply::Null => Some(r#"{"accessToken":null}"#.to_string()),
                Reply::Valid => valid.map(|v| serde_json::json!({ "accessToken": v }).to_string()),
            };
            if let Some(body) = answer {
                if let Ok(raw) = serde_json::value::RawValue::from_string(body) {
                    let line = crate::wire::claude::control_success_line(&id, &raw);
                    send_line(stdin, &String::from_utf8_lossy(&line));
                }
            }
        }
        Seen::Result(is_error, subtype) => {
            if seen.result.is_none() {
                seen.result = Some((is_error, subtype));
                seen.result_ms = Some(ms);
                // The turn is over: closing stdin ends the CLI.
                if reply != Reply::None && stdin.take().is_some() {
                    seen.closed_ms = Some(t.elapsed().as_millis());
                }
            }
        }
        Seen::Other => {}
    }
}

/// One run of the CLI in stream-json host mode, with the extension's
/// entrypoint ([`ENTRYPOINT`]) and the host's refresh offered, which the
/// stock extension never offers: an `initialize`, one user
/// message, the refresh answered per `reply`, until the CLI exits (after its
/// result stdin closes, unless no reply is given) or `limit`; then what it
/// wrote before the exit is read to the end ([`DRAIN`]). Each line is timed
/// when it was read, not when the loop came to it. `wait_401` sets
/// [`WAIT_401_MS`].
fn run_once(claude: &Path, token: &str, reply: Reply, valid: Option<&str>, wait_401: bool, limit: Duration) -> Result<Observed> {
    let home = tempfile::tempdir().map_err(|e| CliError::Msg(format!("a temp HOME: {e}")))?;
    let config = home.path().join(".claude");
    std::fs::create_dir_all(&config)?;
    let mut cmd = Command::new(claude);
    cmd.args(["-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", home.path())
        .env("CLAUDE_CONFIG_DIR", &config)
        .env("CLAUDE_CODE_OAUTH_TOKEN", token)
        .env("CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH", "1")
        .env("CLAUDE_CODE_ENTRYPOINT", ENTRYPOINT)
        .env("DISABLE_AUTOUPDATER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if wait_401 {
        cmd.env("CLAUDE_CODE_OAUTH_401_WAIT_MS", WAIT_401_MS);
    }
    let mut child = cmd.spawn().map_err(|e| CliError::Msg(format!("{}: {e}", claude.display())))?;
    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take().ok_or_else(|| CliError::Msg("no stdout".into()))?;
    let (tx, rx) = std::sync::mpsc::channel::<(Instant, String)>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(std::result::Result::ok) {
            if tx.send((Instant::now(), line)).is_err() {
                return;
            }
        }
    });
    send_line(&mut stdin, r#"{"type":"control_request","request_id":"oauth-t1-init","request":{"subtype":"initialize"}}"#);
    send_line(&mut stdin, r#"{"type":"user","message":{"role":"user","content":"Reply with exactly OK"},"parent_tool_use_id":null,"session_id":"default"}"#);
    let t = Instant::now();
    let mut seen = Observed::default();
    loop {
        if let Some(status) = child.try_wait()? {
            seen.exit_ms = Some(t.elapsed().as_millis());
            seen.exit_code = status.code();
            break;
        }
        if t.elapsed() > limit {
            seen.timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((at, line)) => observe(&mut seen, &mut stdin, &line, at, t, reply, valid),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    // What it wrote before it exited is still read (nothing is answered any more).
    let end = Instant::now() + DRAIN;
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((at, line)) => observe(&mut seen, &mut None, &line, at, t, reply, valid),
            Err(_) => break,
        }
    }
    Ok(seen)
}

/// The claude this Mac's Cursor runs (the bundled CLI), else PATH's.
fn mac_claude() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let ext = home.join(".cursor").join("extensions");
    let bundled = crate::bridge::doctor::pick_bundle(&crate::bridge::doctor::installed_extension_names(&ext)).map(|(_, dir)| ext.join(dir).join("resources").join("native-binary").join("claude")).filter(|p| p.is_file());
    bundled.or_else(|| crate::age_cmd::find_in_path("claude", &std::env::var("PATH").unwrap_or_default()))
}

/// Whether the valid reply may use the sealed setup-token: `Ok` the text of
/// one read of it, whose seal id was checked, for the reply to unseal (F11:
/// the token sent is the one checked, never a second read of a file sealed
/// anew meanwhile); `Err` names why
/// not — none is sealed, or `vm exec` would refuse to unseal it: Anthropic
/// already refused that seal (the rejection recorded in
/// `state/creds.toml`), or whatever else [`refuse_rejected`] refuses on (a
/// store that cannot say which seals were refused is no "none"). The
/// decision is the gate's own, so a refused token is never unsealed or
/// sent here either: the reply would measure a known-bad token as the
/// valid one. Its words become one part of the note's `; ` list.
///
/// [`refuse_rejected`]: crate::bridge::agent::credential::refuse_rejected
fn valid_leg(paths: &Paths) -> std::result::Result<String, String> {
    let path = paths.setup_token_env();
    if crate::bridge::creds::aws_env_state(&path) != crate::bridge::creds::AwsEnvState::Sealed {
        return Err("no sealed token".into());
    }
    let text = crate::bridge::registry::read_regular_file(&path).ok().flatten().ok_or_else(|| "the sealed token cannot be read".to_string())?;
    let tag = crate::bridge::agent::credential::tag_of(&text);
    // On one line (a parse error's text may hold a newline), with no `; ` of its own.
    crate::bridge::agent::credential::refuse_rejected(paths, &tag).map_err(|e| e.to_string().split_whitespace().collect::<Vec<_>>().join(" ").replace("; ", ", "))?;
    Ok(text)
}

/// `lab run oauth-t1` (see the module doc).
pub fn oauth_t1(store: &Keystore, paths: &Paths, cfg: &BridgeConfig) -> Result<MacOutcome> {
    let claude = mac_claude().ok_or_else(|| CliError::Usage("oauth-t1 needs a claude on this Mac (the Cursor extension's, or one on PATH)".into()))?;
    let version = Command::new(&claude).arg("--version").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    let limit = Duration::from_secs(150);
    let bad = refused_token();
    let early = valid_leg(paths);
    if let Err(why) = &early {
        eprintln!("ai-env: oauth-t1: the valid reply will be skipped: {why}");
    }
    // The fourth run is not known yet: it is made only when one of the first three asks for a refresh.
    eprintln!("ai-env: oauth-t1: {} ({version}) as {ENTRYPOINT}: three runs with a refused token{}, at most {} s each (the run with no reply is expected to reach that bound)", claude.display(), if early.is_ok() { ", then a fourth with the valid reply if one of them asks for a refresh" } else { "" }, limit.as_secs());
    let none = run_once(&claude, &bad, Reply::None, None, false, limit)?;
    eprintln!("ai-env: oauth-t1: no reply: {}", none.describe());
    let null = run_once(&claude, &bad, Reply::Null, None, false, limit)?;
    eprintln!("ai-env: oauth-t1: null reply: {}", null.describe());
    let wait = run_once(&claude, &bad, Reply::Null, None, true, limit)?;
    eprintln!("ai-env: oauth-t1: null reply, CLAUDE_CODE_OAUTH_401_WAIT_MS={WAIT_401_MS}: {}", wait.describe());
    // The verdict's evidence: the valid run is made only when one of these asked, so it cannot change it.
    let asked = [&none, &null, &wait].iter().any(|o| o.refresh_ms.is_some());
    // Decided again just before the Touch ID, so a rejection recorded meanwhile counts too; a CLI that asked in
    // none of the runs would never be sent the token, so it is not unsealed for one.
    let leg = valid_leg(paths).and_then(|text| if asked { Ok(text) } else { Err("no run asked for a refresh".to_string()) });
    let valid = match leg {
        Ok(text) => {
            eprintln!("ai-env: oauth-t1: the valid reply needs the sealed setup-token: answer the Touch ID dialog");
            let token = crate::bridge::setup_token::unseal_setup_token_text(store, &text, &cfg.creds.key)?;
            let secret = token.frame_secret();
            drop(token);
            let v = run_once(&claude, &bad, Reply::Valid, Some(secret.expose()), false, limit)?;
            eprintln!("ai-env: oauth-t1: valid reply: {}", v.describe());
            Ok(v)
        }
        Err(why) => {
            eprintln!("ai-env: oauth-t1: the valid reply is skipped: {why}");
            Err(why)
        }
    };
    let verdict = if asked { "refresh-requested" } else { "no-refresh-request" }.to_string();
    let note = format!(
        "{} ({version}) as {ENTRYPOINT} with CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1; none: {}; null: {}; null, CLAUDE_CODE_OAUTH_401_WAIT_MS={WAIT_401_MS}: {}; valid: {}",
        claude.display(),
        none.describe(),
        null.describe(),
        wait.describe(),
        valid.map_or_else(|why| format!("skipped ({why})"), |v| v.describe())
    );
    Ok((verdict, note))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M10: touchid-gui's detached decrypt never inherits a credential from
    /// `lab run`'s environment, as no age call does (`age_cmd`): every name
    /// of `CHILD_ENV_REMOVED` is removed, PATH is set, nothing else changes,
    /// and it asks for exactly the decrypt.
    #[test]
    fn the_detached_unseal_never_inherits_a_credential() {
        let p = Path::new;
        let cmd = detached_cmd(p("/opt/age"), p("/k/identity.txt"), p("/t/out"), p("/t/in.age"));
        let envs: Vec<(String, Option<String>)> = cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect();
        for name in crate::age_cmd::CHILD_ENV_REMOVED {
            assert!(envs.iter().any(|(k, v)| k == name && v.is_none()), "the detached age would inherit {name}");
        }
        assert!(envs.iter().any(|(k, v)| k == "PATH" && v.is_some()), "PATH is set");
        assert_eq!(envs.len(), crate::age_cmd::CHILD_ENV_REMOVED.len() + 1, "nothing else is changed");
        assert!(cmd.get_args().eq(["-d", "-i", "/k/identity.txt", "-o", "/t/out", "/t/in.age"]), "the decrypt alone");
    }

    #[test]
    fn the_ancestry_walk_finds_cursor_or_stops() {
        let tree = |pid: u32| match pid {
            40 => Some((30, "ai-env".to_string())),
            30 => Some((20, "-zsh".to_string())),
            20 => Some((10, "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)".to_string())),
            10 => Some((1, "/Applications/Cursor.app/Contents/MacOS/Cursor".to_string())),
            _ => None,
        };
        assert!(cursor_ancestor(&tree, 40).is_some_and(|c| c.contains("Cursor Helper")));
        let terminal = |pid: u32| match pid {
            40 => Some((30, "ai-env".to_string())),
            30 => Some((20, "-zsh".to_string())),
            20 => Some((1, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal".to_string())),
            _ => None,
        };
        assert_eq!(cursor_ancestor(&terminal, 40), None);
        let looped = |pid: u32| Some((pid, "sh".to_string()));
        assert_eq!(cursor_ancestor(&looped, 7), None, "a pid that is its own parent ends the walk");
    }

    #[test]
    fn the_harness_reads_refresh_requests_and_results() {
        assert_eq!(classify(r#"{"type":"control_request","request_id":"r1","request":{"subtype":"oauth_token_refresh"}}"#), Seen::Refresh("r1".into()));
        assert_eq!(classify(r#"{"type":"control_request","request_id":"r2","request":{"subtype":"can_use_tool"}}"#), Seen::Other);
        assert_eq!(classify(r#"{"type":"result","subtype":"error_during_execution","is_error":true}"#), Seen::Result(true, "error_during_execution".into()));
        assert_eq!(classify(r#"{"type":"result","subtype":"success","is_error":false,"result":"OK"}"#), Seen::Result(false, "success".into()));
        assert_eq!(classify("not json"), Seen::Other);
        let o = Observed { refresh_ms: Some(120), result: Some((true, "login_expired".into())), result_ms: Some(900), exit_ms: Some(950), exit_code: Some(1), closed_ms: None, timed_out: false };
        assert_eq!(o.describe(), "refresh@120 result=login_expired/is_error@900 exit=1@950");
        assert_eq!(Observed { closed_ms: Some(905), ..o }.describe(), "refresh@120 result=login_expired/is_error@900 exit=1@950 stdin-closed@905");
        assert!(Observed { timed_out: true, ..Observed::default() }.describe().ends_with("TIMEOUT"));
    }

    #[test]
    fn the_refused_token_is_built_at_run_time_in_the_setup_token_shape() {
        let t = refused_token();
        assert!(t.starts_with("sk-ant-oat01-") && t.len() > 40);
        assert!(crate::bridge::setup_token::parse_token(&t).is_ok());
    }

    /// The valid reply never uses a seal Anthropic refused: with a rejection
    /// recorded against the sealed setup-token it is skipped, saying why and
    /// what to run (no unseal is attempted); with none sealed it is skipped
    /// as before; a token sealed anew (another seal id) is used again. With a
    /// `state/creds.toml` that cannot be parsed it decides as `vm exec`'s
    /// gate does (`refuse_rejected`), never on a reading of its own.
    #[test]
    fn the_valid_reply_is_skipped_for_a_refused_seal() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        assert_eq!(valid_leg(&paths), Err("no sealed token".to_string()));
        std::fs::create_dir_all(paths.setup_token_env().parent().unwrap()).unwrap();
        std::fs::write(paths.setup_token_env(), crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        assert!(valid_leg(&paths).is_ok());
        let tag = crate::bridge::agent::credential::seal_tag(&paths.setup_token_env()).unwrap();
        crate::bridge::agent::credential::record_rejection(&paths, "microvm-refused", &tag, "text");
        let why = valid_leg(&paths).unwrap_err();
        assert!(why.contains(&format!("seal {tag}")) && why.contains("refused by Anthropic") && why.contains("microvm-refused") && why.contains("ai-env creds setup-token"), "{why}");
        assert!(!why.contains(';'), "one part of the note's `; ` list: {why}");
        std::fs::write(paths.setup_token_env(), crate::container::write(b"age-encryption.org/v1\n-> x\n--- z\n")).unwrap();
        assert!(valid_leg(&paths).is_ok(), "a new seal is not the refused one");
        std::fs::write(paths.creds_state(), "[[rejected]\nnot toml").unwrap();
        let tag = crate::bridge::agent::credential::seal_tag(&paths.setup_token_env()).unwrap();
        let gate = crate::bridge::agent::credential::refuse_rejected(&paths, &tag).map_err(|e| e.to_string());
        assert_eq!(valid_leg(&paths).is_err(), gate.is_err(), "as the gate decides ({gate:?}): {:?}", valid_leg(&paths).err());
        if let Err(why) = valid_leg(&paths) {
            assert!(!why.contains('\n') && !why.contains(';'), "one line, one part of the note's `; ` list: {why}");
        }
    }

    /// F11: the valid leg hands the reply the very text whose seal id it
    /// checked, which the reply unseals (`unseal_setup_token_text`): a token
    /// sealed anew once the check was made (another seal id, maybe a refused
    /// one) never stands in for the checked one.
    #[test]
    fn the_valid_leg_hands_over_the_text_whose_seal_it_checked() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.setup_token_env().parent().unwrap()).unwrap();
        let checked = crate::container::write(b"age-encryption.org/v1\n-> x\n--- checked\n");
        std::fs::write(paths.setup_token_env(), &checked).unwrap();
        let tag = crate::bridge::agent::credential::seal_tag(&paths.setup_token_env()).unwrap();
        let text = valid_leg(&paths).unwrap_or_else(|why| panic!("{why}"));
        std::fs::write(paths.setup_token_env(), crate::container::write(b"age-encryption.org/v1\n-> x\n--- anew\n")).unwrap();
        assert!(text == checked, "the text of the read checked ({} bytes, not {})", text.len(), checked.len());
        assert_eq!(crate::bridge::agent::credential::tag_of(&text), tag, "the seal id checked");
        assert_ne!(crate::bridge::agent::credential::seal_tag(&paths.setup_token_env()), Some(tag), "the file holds another seal now");
    }

    /// A CLI script for [`run_once`] in `dir`.
    fn cli(dir: &Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("claude");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// The real CLI's condition for asking its host for a refresh (2.1.288's
    /// `sdkHostOffersOAuthRefresh`), as shell that sets `offered`:
    /// `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH` set and an entrypoint of its
    /// `SDK_OAUTH_REFRESH_ENTRYPOINTS`. Every stand-in here asks only under
    /// it: one that asked whatever its environment hid a harness that never
    /// offered the refresh (F1).
    const OFFERED: &str = "case \"${CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH:-}:${CLAUDE_CODE_ENTRYPOINT:-}\" in 1:claude-desktop|1:local-agent|1:claude-vscode) offered=1 ;; *) offered= ;; esac\n";

    /// What a CLI wrote before it exited is still read: here its parent
    /// process exits at once and a child of it writes the refresh request and
    /// the result 300 ms later, on the stdout it kept. The harness used to see
    /// the exit first and stop, reading neither (a result recorded as none).
    #[test]
    fn run_once_reads_what_the_cli_wrote_before_its_exit() {
        let d = tempfile::tempdir().unwrap();
        let script = ["#!/bin/sh\n", OFFERED, "( sleep 0.3\n  if [ -n \"$offered\" ]; then printf '%s\\n' '{\"type\":\"control_request\",\"request_id\":\"r1\",\"request\":{\"subtype\":\"oauth_token_refresh\"}}'; fi\n  printf '%s\\n' '{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true}' ) &\nexit 0\n"].concat();
        let seen = run_once(&cli(d.path(), &script), "unused", Reply::None, None, false, Duration::from_secs(10)).unwrap();
        assert_eq!(seen.exit_code, Some(0));
        assert!(seen.refresh_ms.is_some_and(|ms| ms >= 250), "{}", seen.describe());
        assert_eq!(seen.result, Some((true, "error_during_execution".to_string())), "{}", seen.describe());
        assert!(!seen.timed_out);
    }

    /// With no reply the CLI's stdin stays open after its result, so the exit
    /// timed is its own: this CLI exits 3 when its stdin is still open 600 ms
    /// after its result, 7 when it was closed. A run that replies (null)
    /// closes stdin at the result, as before, and says when.
    #[test]
    fn with_no_reply_the_clis_exit_is_its_own() {
        let d = tempfile::tempdir().unwrap();
        let script = ["#!/bin/sh\n", OFFERED, "while IFS= read -r line; do\n  case \"$line\" in *'\"type\":\"user\"'*) break ;; esac\ndone\nif [ -n \"$offered\" ]; then printf '%s\\n' '{\"type\":\"control_request\",\"request_id\":\"r1\",\"request\":{\"subtype\":\"oauth_token_refresh\"}}'; fi\nprintf '%s\\n' '{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true}'\nexec 3<&0\n( cat <&3 >/dev/null; : >\"$HOME/eof\" ) >/dev/null 2>&1 &\nsleep 0.6\nif [ -e \"$HOME/eof\" ]; then exit 7; fi\nexit 3\n"].concat();
        let claude = cli(d.path(), &script);
        let none = run_once(&claude, "unused", Reply::None, None, false, Duration::from_secs(10)).unwrap();
        assert_eq!((none.exit_code, none.closed_ms), (Some(3), None), "{}", none.describe());
        assert!(none.refresh_ms.is_some() && none.result.is_some(), "{}", none.describe());
        let null = run_once(&claude, "unused", Reply::Null, None, false, Duration::from_secs(10)).unwrap();
        assert_eq!(null.exit_code, Some(7), "{}", null.describe());
        assert!(null.closed_ms.is_some_and(|c| null.result_ms.is_some_and(|r| c >= r)), "closed at the result: {}", null.describe());
        assert!(null.describe().contains(" stdin-closed@"), "{}", null.describe());
    }

    /// F1: every run offers the CLI the host's refresh with the extension's
    /// entrypoint (`CLAUDE_CODE_ENTRYPOINT=claude-vscode` beside
    /// `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1`), so a CLI that asks only when
    /// offered ([`OFFERED`]) asks, and the null reply reaches it: it exits 4
    /// once that reply came back (1 otherwise). It notes its environment: the
    /// knob run (`wait_401`) adds `CLAUDE_CODE_OAUTH_401_WAIT_MS=5000` alone,
    /// never `CLAUDE_CODE_AUTH_FAIL_EXIT_MS` (it acts only for a remote child,
    /// which ai-env's CLI never is). Without the entrypoint it never asked
    /// (`refresh@-`, exit 1).
    #[test]
    fn run_once_offers_the_cli_the_hosts_refresh_with_the_extensions_entrypoint() {
        let d = tempfile::tempdir().unwrap();
        let script = ["#!/bin/sh\n", OFFERED, "printf '%s %s %s\\n' \"${CLAUDE_CODE_ENTRYPOINT:--}\" \"${CLAUDE_CODE_OAUTH_401_WAIT_MS:--}\" \"${CLAUDE_CODE_AUTH_FAIL_EXIT_MS:--}\" >>\"$(dirname \"$0\")/env\"\nwhile IFS= read -r line; do\n  case \"$line\" in *'\"type\":\"user\"'*) break ;; esac\ndone\nif [ -n \"$offered\" ]; then\n  printf '%s\\n' '{\"type\":\"control_request\",\"request_id\":\"r1\",\"request\":{\"subtype\":\"oauth_token_refresh\"}}'\n  IFS= read -r answer\n  case \"$answer\" in *'\"request_id\":\"r1\"'*'\"accessToken\":null'*) : >\"$HOME/answered\" ;; esac\nfi\nprintf '%s\\n' '{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true}'\ncat >/dev/null\nif [ -e \"$HOME/answered\" ]; then exit 4; fi\nexit 1\n"].concat();
        let claude = cli(d.path(), &script);
        for wait_401 in [false, true] {
            // A bound for a hung CLI alone: a loaded Mac can take seconds to start a script just written.
            let seen = run_once(&claude, "unused", Reply::Null, None, wait_401, Duration::from_secs(60)).unwrap();
            assert!(seen.refresh_ms.is_some(), "the CLI was never offered the host's refresh: {}", seen.describe());
            assert_eq!(seen.exit_code, Some(4), "the null reply reached the CLI: {}", seen.describe());
        }
        let env = std::fs::read_to_string(d.path().join("env")).unwrap();
        assert_eq!(env, "claude-vscode - -\nclaude-vscode 5000 -\n", "the entrypoint on every run, the 401 wait on the knob run alone, never the auth-fail exit");
    }
}
