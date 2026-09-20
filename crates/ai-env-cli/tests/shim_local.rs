//! Native shim tests (`--features shim`): the `/health` listener serves the
//! Health document over plain HTTP/1.1. No reqwest here — the shim graph has
//! no TLS client, so the request is written by hand on a TcpStream.
use ai_env_cli::shim::health::{router, ShimState};
use ai_env_cli::wire::frame::{Health, HealthStatus};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn health_reports_shim_version() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(ShimState::new("/nonexistent/claude".into()));
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });

    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    let body = text.split("\r\n\r\n").nth(1).expect("body");
    let h: Health = serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(h.status, HealthStatus::Ok);
    assert_eq!(h.shim_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(h.claude_version, None, "no claude at the configured path");
    assert!(!h.run_hook_seen);
    assert!(h.microvm_id.is_none());
}

// ---- the real binary: `ai-env shim` as the image ENTRYPOINT runs it --------

/// The `ai-env` built for this test run (same feature set as the tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// `ai-env <args>` with an EMPTY environment (`env -i`): PID 1 in the VM has
/// no HOME, no PATH, no keystore, and the shim must not need any of them.
fn ai_env(args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_clear().args(args).stdin(Stdio::null());
    cmd
}

#[test]
fn shim_help_lists_the_entrypoint_surface() {
    let out = ai_env(&["shim", "--help"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    for flag in ["--app-port", "--hooks-port", "--code-port", "--claude", "--home", "--uid", "--echo", "--delay-run"] {
        assert!(text.contains(flag), "{flag} missing from:\n{text}");
    }
    for default in ["8080", "9000", "9418", "/Users/mike", "1000"] {
        assert!(text.contains(default), "default {default} missing from:\n{text}");
    }
}

#[test]
fn shim_without_claude_is_a_usage_error() {
    let out = ai_env(&["shim"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--claude"), "{err}");
}

/// A child that is killed on drop, so a failing assertion never leaves a
/// listener behind.
struct Spawned(std::process::Child);

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn shim_binary_serves_health_on_an_ephemeral_port() {
    let mut child = ai_env(&["shim", "--claude", "/nonexistent", "--app-port", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let child = Spawned(child);

    // Read stderr on a thread so the wait for the listening line is bounded
    // (a hung shim fails the test instead of blocking it).
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    let addr: SocketAddr = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let line = rx.recv_timeout(left).unwrap_or_else(|e| panic!("no listening line within 10 s ({e}); stderr so far: {seen:?}"));
        if let Some(rest) = line.strip_prefix("ai-env: shim ").and_then(|l| l.split(" listening on ").nth(1)) {
            break rest.trim().parse().unwrap_or_else(|e| panic!("{e}: {line:?}"));
        }
        seen.push(line);
    };
    assert!(addr.ip().is_unspecified(), "bound on all interfaces: {addr}");
    assert_ne!(addr.port(), 0, "the ACTUALLY bound port, not the requested 0");

    let target = SocketAddr::from(([127, 0, 0, 1], addr.port()));
    let mut s = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(5)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("GET /health HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    let body = text.split("\r\n\r\n").nth(1).expect("body");
    assert!(body.contains("\"status\":\"ok\""), "{body}");
    let h: Health = serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(h.shim_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(h.claude_version, None, "/nonexistent is null, and would be probed again");

    drop(child);
}
