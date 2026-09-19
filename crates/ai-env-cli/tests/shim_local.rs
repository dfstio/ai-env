//! Native shim tests (`--features shim`): the `/health` listener serves the
//! Health document over plain HTTP/1.1. No reqwest here — the shim graph has
//! no TLS client, so the request is written by hand on a TcpStream.
use ai_env_cli::shim::health::{router, ShimState};
use ai_env_cli::wire::frame::{Health, HealthStatus};
use std::sync::Arc;
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
