//! The template's sources against ai-env-source's conformance checks (P-R85): offline, so the
//! `HttpJsonSource` below never reaches its address.

#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../src/sources.rs"]
mod sources;

use std::sync::Arc;
use std::time::Duration;

use ai_env_source::testkit::{assert_conforms, context};
use ai_env_source::{CallRequest, DataSource, Limits, SourceError};
use serde_json::json;

#[tokio::test]
async fn the_example_sources_conform() {
    assert_conforms(Arc::new(sources::EchoSource::new("example-echo"))).await;
    assert_conforms(Arc::new(sources::HttpJsonSource::new("example-http", "http://127.0.0.1:9", vec!["/v1/".into()], None))).await;
}

/// `HttpJsonSource` refuses, before any I/O, a path outside its prefixes and one the URL parser would read
/// otherwise: percent-encoded dots, a backslash, a prefix not on a segment boundary, a query, a fragment, a
/// control character (the parser drops it, and `.\t.` becomes `..`).
#[tokio::test]
async fn the_http_source_refuses_paths_outside_its_prefixes() {
    let source = sources::HttpJsonSource::new("example-http", "http://127.0.0.1:9", vec!["/v1/status".into()], None);
    let get = |path: &str| source.call(CallRequest::new("get", json!({ "path": path })), context("example-http", Limits::DEFAULT, Duration::from_secs(2)));
    let refused = [
        "/v1/status/%2e%2e/%2e%2e/admin",
        "/v1/status/.%2E/admin",
        "/v1/status\\%2e%2e\\admin",
        "/v1/status\\..\\admin",
        "/v1/statusX",
        "/v1/status/../admin",
        "/v1/status/.\t./admin",
        "/v1/status/\n",
        "/v1/status/ x",
        "/v1/status?admin=1",
        "/v1/status#admin",
        "/v1/status/é",
        "v1/status",
        "/v2/status",
        "",
    ];
    for path in refused {
        match get(path).await {
            Err(SourceError::InvalidArgument(m)) => assert_eq!(m, "params: path is not allowed", "{path:?}"),
            other => panic!("{path:?} is refused before any I/O: {other:?}"),
        }
    }
    // These pass the check (the request then fails on the closed port, whatever the error).
    for path in ["/v1/status", "/v1/status/", "/v1/status/x.json"] {
        assert!(!matches!(get(path).await, Err(SourceError::InvalidArgument(_))), "{path:?} is allowed");
    }
}
