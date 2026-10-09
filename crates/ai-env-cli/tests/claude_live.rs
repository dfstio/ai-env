//! T7.2 (S7, live, this Mac): the sealed setup-token drives the real `claude`.
//! `#[ignore]`d, and skipped unless `AI_ENV_CLAUDE_TESTS=1` (`make
//! test-claude`): these make real model requests with the operator's token,
//! unsealed once for the run (one Touch ID). Every `claude` runs with an empty
//! temporary `CLAUDE_CONFIG_DIR` and HOME, the token in its environment as
//! `CLAUDE_CODE_OAUTH_TOKEN`, and nothing else of this Mac's login. Output is
//! measured, never the token: assertion messages show lengths and fixed
//! words, and every run ends by checking that the token is in neither of its
//! outputs nor in any file under its temporary HOME. Never part of `make test`.
use ai_env_cli::bridge::config::{BridgeConfig, Paths};
use ai_env_cli::store::Keystore;
use ai_env_cli::wire::redact::Secret;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(180);

fn live() -> bool {
    if std::env::var("AI_ENV_CLAUDE_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_CLAUDE_TESTS=1 (make test-claude) to run the live claude tests");
    false
}

/// The real `claude` on PATH.
fn claude() -> PathBuf {
    let path = std::env::var("PATH").unwrap_or_default();
    ai_env_cli::age_cmd::find_in_path("claude", &path).expect("a claude on PATH")
}

/// The sealed setup-token, unsealed once for the whole run (one Touch ID).
fn token() -> &'static Secret<String> {
    static TOKEN: OnceLock<Secret<String>> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let paths = Paths::resolve().expect("the bridge root");
        let key = BridgeConfig::load(&paths).ok().flatten().unwrap_or_default().creds.key;
        let store = Keystore::resolve(None).expect("the keystore");
        let t = ai_env_cli::bridge::setup_token::unseal_setup_token(&store, &paths, &key).unwrap_or_else(|e| panic!("unsealing the setup-token: {e}"));
        t.frame_secret()
    })
}

/// Does `hay` hold the token's random part (after `sk-ant-<kind>-`, which
/// the CLI may well print on its own), or any 16-byte piece of it?
fn holds_token(hay: &[u8]) -> bool {
    let t = token().expose().as_str();
    let random = t.strip_prefix("sk-ant-").and_then(|r| r.split_once('-')).map_or(t, |(_, tail)| tail).as_bytes();
    let w = random.len().min(16);
    w > 0 && random.windows(w).any(|piece| hay.windows(w).any(|h| h == piece))
}

/// The token is in neither output of a run, nor in any file under its
/// temporary HOME: a copy there is the CLI's own (plan tree E), named by its
/// path under that HOME, never by value.
fn sweep(out: &Output, home: &Path) {
    for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        assert!(!holds_token(bytes), "the token (or a 16-byte piece of it) is in claude's {stream}");
    }
    let mut dirs = vec![home.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.is_dir() {
                dirs.push(path);
            } else if meta.is_file() {
                let bytes = std::fs::read(&path).unwrap_or_default();
                assert!(!holds_token(&bytes), "the token (or a 16-byte piece of it) is in {} under claude's temporary HOME: the CLI's own copy, plan tree E", path.strip_prefix(home).unwrap_or(&path).display());
            }
        }
    }
}

/// `claude <args>` with the token, `home` as HOME and its `.claude` as the
/// config dir, stdin `input` (or none); both outputs drained while it runs
/// (a stream-json session can outgrow a pipe, which would stall it), bounded
/// by [`LIMIT`]; then [`sweep`].
fn run_in(home: &Path, args: &[&str], input: Option<&str>) -> Output {
    use std::io::Read;
    fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    }
    let config = home.join(".claude");
    std::fs::create_dir_all(&config).unwrap();
    let mut cmd = Command::new(claude());
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", home)
        .env("CLAUDE_CONFIG_DIR", &config)
        .env("CLAUDE_CODE_OAUTH_TOKEN", token().expose())
        .env("DISABLE_AUTOUPDATER", "1")
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("claude starts");
    if let (Some(text), Some(mut w)) = (input, child.stdin.take()) {
        use std::io::Write as _;
        w.write_all(text.as_bytes()).unwrap();
    }
    let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("claude {:?} ran past {LIMIT:?}", args.first());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = Output { status, stdout: stdout.join().unwrap_or_default(), stderr: stderr.join().unwrap_or_default() };
    eprintln!("claude {:?}: exit {:?} in {} ms, {} bytes out, {} bytes err", args.first(), out.status.code(), started.elapsed().as_millis(), out.stdout.len(), out.stderr.len());
    sweep(&out, home);
    out
}

/// [`run_in`] a fresh temporary HOME, returned for a later `--resume`.
fn run(args: &[&str], input: Option<&str>) -> (Output, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let out = run_in(home.path(), args, input);
    (out, home)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

/// The JSON objects of a stream-json output, one per line.
fn events(out: &[u8]) -> Vec<serde_json::Value> {
    text(out).lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// A stream-json session with a Bash tool call: init, the tool's use, the
/// assistant's answer and a successful result carrying the tool's output.
#[test]
#[ignore = "live: AI_ENV_CLAUDE_TESTS=1 (make test-claude)"]
fn live_claude_stream_json_session_with_a_tool_call() {
    if !live() {
        return;
    }
    let (out, _home) = run(
        &["-p", "Run the shell command `echo s7-tool-ran` with the Bash tool, then reply with exactly what it printed.", "--output-format", "stream-json", "--verbose", "--allowedTools", "Bash(echo:*)"],
        None,
    );
    assert!(out.status.code() == Some(0), "exit {:?}, {} bytes of stderr", out.status.code(), out.stderr.len());
    let ev = events(&out.stdout);
    let kind = |t: &str, s: Option<&str>| ev.iter().any(|e| e["type"] == t && s.is_none_or(|s| e["subtype"] == s));
    assert!(kind("system", Some("init")), "an init event");
    assert!(ev.iter().any(|e| e["type"] == "assistant" && e.to_string().contains("\"tool_use\"")), "a tool use");
    let result = ev.iter().rev().find(|e| e["type"] == "result").expect("a result event");
    assert_eq!(result["is_error"], false, "{}", result.get("subtype").cloned().unwrap_or_default());
    assert!(result["result"].as_str().is_some_and(|r| r.contains("s7-tool-ran")), "the tool's output in the result");
}

/// `--resume` carries the earlier session's context: the second run, in the
/// first one's HOME and config dir, names the word the first was given.
#[test]
#[ignore = "live: AI_ENV_CLAUDE_TESTS=1 (make test-claude)"]
fn live_claude_resume_carries_context() {
    if !live() {
        return;
    }
    let (out, home) = run(&["-p", "Remember the word heliotrope. Reply with exactly OK.", "--output-format", "json"], None);
    assert!(out.status.code() == Some(0), "exit {:?}, {} bytes of stderr", out.status.code(), out.stderr.len());
    // The session lives in that run's config dir: the resume runs in the same HOME.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let session = v["session_id"].as_str().unwrap().to_string();
    let out = run_in(home.path(), &["-p", "--resume", &session, "Which word did I ask you to remember? Reply with the word only.", "--output-format", "json"], None);
    assert!(out.status.code() == Some(0), "exit {:?}, {} bytes of stderr", out.status.code(), out.stderr.len());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["result"].as_str().is_some_and(|r| r.to_ascii_lowercase().contains("heliotrope")), "the resumed session remembers");
}

/// An inference-only token cannot drive Remote Control.
#[test]
#[ignore = "live: AI_ENV_CLAUDE_TESTS=1 (make test-claude)"]
fn live_claude_remote_control_needs_a_full_login() {
    if !live() {
        return;
    }
    let (out, _home) = run(&["remote-control"], None);
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(all.contains("Remote Control requires a full-scope login token"), "exit {:?}, {} bytes of output", out.status.code(), all.len());
}

/// `--bare` never reads CLAUDE_CODE_OAUTH_TOKEN (why `vm exec` refuses
/// `claude --bare` with a credential).
#[test]
#[ignore = "live: AI_ENV_CLAUDE_TESTS=1 (make test-claude)"]
fn live_claude_bare_is_not_logged_in() {
    if !live() {
        return;
    }
    let (out, _home) = run(&["--bare", "-p", "Reply with exactly OK.", "--output-format", "json"], None);
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr)).to_ascii_lowercase();
    assert!(out.status.code() != Some(0) || all.contains("not logged in") || all.contains("\"is_error\":true"), "--bare answered as if logged in: exit {:?}", out.status.code());
}
