//! Shared helpers for tests/infra.rs.
#![allow(dead_code)]
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How long [`run`] lets one `ai-env` run.
pub const RUN_LIMIT: Duration = Duration::from_secs(120);

/// The `ai-env` built for this test run.
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// `ai-env <args>` with a clean bridge + keystore under `tmp` and nothing of
/// the developer's shell that would steer it or the fakes: no AWS, Pulumi or
/// `CLAUDE_CODE_*` variable, no `AI_ENV_*` but the two set here, and no
/// `FAKE_*` knob (an exported `FAKE_AGE_HANG` would hang every decrypt); a
/// test sets what it needs after this.
pub fn ai_env(tmp: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    // Removed first: a removal after the settings below would undo them.
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("AI_ENV_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") {
            cmd.env_remove(&k);
        }
    }
    cmd.args(args)
        .env("HOME", tmp)
        .env("AI_ENV_BRIDGE_DIR", tmp.join("bridge"))
        .env("AI_ENV_DIR", tmp.join("keys"))
        .env_remove("AI_ENV_BRIDGE_CONFIG")
        .stdin(Stdio::null());
    cmd
}

/// The isolation of [`ai_env`] for any other child (a `make`, a script under
/// test): HOME, the bridge directory and the keystore under `tmp`, no bridge
/// config, none of the developer's variables [`ai_env`] removes, and none of
/// an outer make's state (a `make test` above cargo would pass its -i/-k/-n
/// and command-line variables down through MAKEFLAGS); stdin null.
pub fn isolate<'a>(cmd: &'a mut Command, tmp: &Path) -> &'a mut Command {
    // Removed first, as in `ai_env`.
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("AI_ENV_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env("HOME", tmp)
        .env("AI_ENV_BRIDGE_DIR", tmp.join("bridge"))
        .env("AI_ENV_DIR", tmp.join("keys"))
        .env_remove("AI_ENV_BRIDGE_CONFIG")
        .stdin(Stdio::null());
    for k in ["MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"] {
        cmd.env_remove(k);
    }
    cmd
}

/// `cmd` to the end, its stdout and stderr captured, bounded by [`RUN_LIMIT`].
pub fn run(cmd: &mut Command) -> Output {
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    finish(child, RUN_LIMIT, "ai-env")
}

/// Wait for `child` for at most `limit`, draining its piped stdout and stderr
/// on two threads meanwhile (a child that fills a pipe nobody reads blocks
/// until it is killed). Past `limit` the child is killed and the test fails
/// naming `what`.
pub fn finish(mut child: Child, limit: Duration, what: &str) -> Output {
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
    let (out, err) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for the child") {
            break status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: still running after {limit:?}, killed");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() }
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}
