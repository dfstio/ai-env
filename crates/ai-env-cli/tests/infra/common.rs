//! Shared helpers for tests/infra.rs.
#![allow(dead_code)]
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The `ai-env` built for this test run.
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// `ai-env <args>` with a clean bridge + keystore under `tmp` and no AWS or
/// Pulumi environment leaking in from the developer's shell.
pub fn ai_env(tmp: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("HOME", tmp)
        .env("AI_ENV_BRIDGE_DIR", tmp.join("bridge"))
        .env("AI_ENV_DIR", tmp.join("keys"))
        .env_remove("AI_ENV_BRIDGE_CONFIG")
        .stdin(Stdio::null());
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AWS_") || k.starts_with("PULUMI_") {
            cmd.env_remove(&k);
        }
    }
    cmd
}

/// The isolation of [`ai_env`] for any other child (a `make`, a script under
/// test): HOME, the bridge directory and the keystore under `tmp`, no bridge
/// config, no AWS or Pulumi variables, and none of an outer make's state (a
/// `make test` above cargo would pass its -i/-k/-n and command-line
/// variables down through MAKEFLAGS); stdin null.
pub fn isolate<'a>(cmd: &'a mut Command, tmp: &Path) -> &'a mut Command {
    cmd.env("HOME", tmp)
        .env("AI_ENV_BRIDGE_DIR", tmp.join("bridge"))
        .env("AI_ENV_DIR", tmp.join("keys"))
        .env_remove("AI_ENV_BRIDGE_CONFIG")
        .stdin(Stdio::null());
    for k in ["MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"] {
        cmd.env_remove(k);
    }
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AWS_") || k.starts_with("PULUMI_") {
            cmd.env_remove(&k);
        }
    }
    cmd
}

pub fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("spawn ai-env")
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}
