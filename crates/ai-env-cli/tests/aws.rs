//! Bridge tests that touch the AWS SDK types and the TLS/WebSocket request
//! path (`--features bridge`). Offline unless marked `#[ignore]`. Nothing
//! here mutates the process environment: the region test that does lives
//! alone in `tests/aws_region.rs`.
use ai_env_cli::bridge::api::{hooks_config, idle_policy, sdk_config, Call, FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, VmState};
use ai_env_cli::bridge::tls;
use ai_env_cli::bridge::transport::agent_request;
use ai_env_cli::wire::redact::Secret;
use aws_sdk_lambdamicrovms::types::{HookState, IdlePolicy, MicrovmHooks};

#[test]
fn idle_policy_builder_missing_fields_is_err() {
    assert!(IdlePolicy::builder().build().is_err(), "the SDK builder trap: three required fields");
    let ok = idle_policy(&IdleSpec { max_idle_s: 300, suspended_s: 28_800, auto_resume: true }).unwrap();
    assert_eq!(ok.max_idle_duration_seconds(), 300);
    assert_eq!(ok.suspended_duration_seconds(), 28_800);
    assert!(ok.auto_resume_enabled());
}

#[test]
fn microvm_hooks_builder_default_trap() {
    let h = MicrovmHooks::builder().build();
    assert_eq!(h.run(), &HookState::Disabled, "default is DISABLED — never rely on it");
    assert_eq!(h.run_timeout_in_seconds(), 1);
}

#[test]
fn hooks_config_matches_spec() {
    let h = hooks_config();
    assert_eq!(h.port(), Some(9000));
    let m = h.microvm_hooks().expect("microvm hooks");
    assert_eq!((m.run(), m.run_timeout_in_seconds()), (&HookState::Enabled, 30));
    assert_eq!((m.resume(), m.resume_timeout_in_seconds()), (&HookState::Enabled, 30));
    assert_eq!((m.suspend(), m.suspend_timeout_in_seconds()), (&HookState::Enabled, 30));
    assert_eq!((m.terminate(), m.terminate_timeout_in_seconds()), (&HookState::Enabled, 60));
    let i = h.microvm_image_hooks().expect("image hooks");
    assert_eq!((i.ready(), i.ready_timeout_in_seconds()), (&HookState::Enabled, 600));
    assert_eq!((i.validate(), i.validate_timeout_in_seconds()), (&HookState::Enabled, 300));
}

#[test]
fn derive_accept_key_kat() {
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
    // RFC 6455 §1.3 / §4.2.2 example handshake: public spec constants, not credentials.
    assert_eq!(derive_accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn ws_request_bytes() {
    use tokio_tungstenite::tungstenite::handshake::client::generate_request;
    let req = agent_request("mvm-1.microvms.eu-central-1.on.aws", &Secret::new("tok".into()), 8080).unwrap();
    let (bytes, _key) = generate_request(req).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("GET /agent HTTP/1.1\r\n"), "{text}");
    let lower = text.to_ascii_lowercase();
    assert!(lower.contains("host: mvm-1.microvms.eu-central-1.on.aws"), "{text}");
    assert!(lower.contains("x-aws-proxy-auth: tok"), "{text}");
    assert!(lower.contains("x-aws-proxy-port: 8080"), "{text}");
    assert!(lower.contains("sec-websocket-version: 13"), "{text}");
    assert!(lower.contains("upgrade: websocket"), "{text}");
    assert!(!lower.contains("sec-websocket-protocol"), "subprotocols are the documented fallback only: {text}");
}

#[tokio::test]
async fn sdk_config_installs_the_bridge_http_client() {
    let cfg = sdk_config().await;
    assert_eq!(cfg.region().map(|r| r.as_ref().to_string()), Some("eu-central-1".to_string()));
    assert!(cfg.http_client().is_some(), "sdk_config must install bridge::tls::sdk_http_client(), never the SDK default");
}

#[test]
fn tls_policy_holds() {
    assert_eq!(tls::root_store().roots.len(), 4);
    assert_eq!(tls::PROTOCOL_VERSIONS.len(), 1);
    assert!(matches!(tls::ws_connector(), tokio_tungstenite::Connector::Rustls(_)));
}

/// Gate for the `#[ignore]`d live tests: says so on stderr instead of passing silently.
fn live() -> bool {
    if std::env::var("AI_ENV_AWS_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_AWS_TESTS=1 to run live tests");
    false
}

#[tokio::test]
#[ignore = "live TLS handshake; run with AI_ENV_AWS_TESTS=1 cargo test --test aws -- --ignored"]
async fn tls_live_amazontrust() {
    if !live() {
        return;
    }
    let client = tls::reqwest_client().unwrap();
    let r = client.get("https://www.amazontrust.com/repository/").send().await.unwrap();
    assert!(r.status().is_success(), "{}", r.status());
}

fn spec(token: &str) -> RunSpec {
    RunSpec {
        image_arn: "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent".into(),
        image_version: "1".into(),
        execution_role_arn: None,
        egress_connectors: vec![],
        idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
        max_duration_s: 900,
        run_hook_payload: "{\"v\":1}".into(),
        client_token: token.into(),
    }
}

#[tokio::test]
async fn fake_api_lifecycle() {
    let api = FakeMicrovmApi::new();
    let vm = api.run(&spec("t1")).await.unwrap();
    assert_eq!(vm.state, VmState::Pending);
    assert_eq!(vm.endpoint, format!("{}.microvms.eu-central-1.on.aws", vm.id));
    let again = api.run(&spec("t1")).await.unwrap();
    assert_eq!(again.id, vm.id, "same client_token → same VM (idempotent RunMicrovm)");
    assert!(api.suspend(&vm.id).await.is_err(), "suspend needs RUNNING");
    api.advance_all();
    assert_eq!(api.get(&vm.id).await.unwrap().state, VmState::Running);
    api.suspend(&vm.id).await.unwrap();
    assert_eq!(api.get(&vm.id).await.unwrap().state, VmState::Suspended);
    api.resume(&vm.id).await.unwrap();
    assert_eq!(api.get(&vm.id).await.unwrap().state, VmState::Running);
    let tok = api.create_auth_token(&vm.id, 60, 8080).await.unwrap();
    assert!(tok.headers.contains_key("X-aws-proxy-auth"));
    assert_eq!(tok.port, 8080);
    assert!(tok.expires_at_unix > ai_env_cli::wire::time::unix_now() + 3500);
    assert_eq!(format!("{:?}", tok.headers["X-aws-proxy-auth"]), "[redacted:len=223]");
    api.terminate(&vm.id).await.unwrap();
    assert_eq!(api.get(&vm.id).await.unwrap().state, VmState::Terminated);
    assert_eq!(api.list(Some(&spec("x").image_arn)).await.unwrap().len(), 1);
    assert_eq!(api.list(Some("other")).await.unwrap().len(), 0);
    assert_eq!(api.list_managed_images().await.unwrap()[0].arn, "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1");
    let calls = api.calls();
    assert_eq!(calls[0], Call::Run { client_token: "t1".into() });
    assert_eq!(calls[1], Call::Run { client_token: "t1".into() });
    assert_eq!(calls[2], Call::Suspend(vm.id.clone()));
    assert!(calls.contains(&Call::Token { id: vm.id.clone(), minutes: 60, port: 8080 }));
    assert_eq!(*calls.last().unwrap(), Call::ListImages);
}

#[tokio::test]
async fn fake_api_fail_next() {
    let api = FakeMicrovmApi::new();
    api.fail_next(ai_env_cli::bridge::errors::BridgeError::Quota("memory".into()));
    let e = api.run(&spec("t")).await.unwrap_err();
    let c: ai_env_cli::errors::CliError = e.into();
    assert_eq!(c.exit_code(), 7);
    assert!(api.run(&spec("t")).await.is_ok(), "failure is one-shot");
}
