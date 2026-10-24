//! Bridge tests that touch the AWS SDK types and the TLS/WebSocket request
//! path (`--features bridge`). Offline unless marked `#[ignore]`. Nothing
//! here mutates the process environment: the region test that does lives
//! alone in `tests/aws_region.rs`.
use ai_env_cli::bridge::api::{
    hooks_config, idle_policy, managed_connector_arn, normalize_endpoint, sdk_config, Call, EndpointClient, FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, VmState, FAKE_IMAGE_ARN,
};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::tls;
use ai_env_cli::bridge::transport::agent_request;
use ai_env_cli::wire::frame::RunHookPayload;
use ai_env_cli::wire::redact::Secret;
use aws_sdk_lambdamicrovms::types::{HookState, IdlePolicy, MicrovmHooks};
// S4 step 4/5: the real client, its credentials and the HTTPS endpoint.
use ai_env_cli::bridge::api::{AuthToken, TOKEN_HEADER};
use ai_env_cli::bridge::vm::client::{connect, run_request, sdk_config_for, RuntimeCreds};
use ai_env_cli::bridge::vm::health::HttpsEndpoint;
use ai_env_cli::errors::CliError;
use aws_sdk_lambdamicrovms::config::Credentials;

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

/// infra/image-config.json (what the Pulumi program deploys) and
/// `hooks_config()` (what the Rust side assumes) are one contract: plan D19.
#[test]
fn image_config_matches_hooks_config() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/image-config.json")).unwrap();
    let c: serde_json::Value = serde_json::from_str(&text).unwrap();
    let h = hooks_config();
    let (m, i) = (h.microvm_hooks().unwrap(), h.microvm_image_hooks().unwrap());
    let hooks = &c["hooks"];
    let n = |k: &str| hooks[k].as_i64().unwrap_or_else(|| panic!("hooks.{k} missing"));
    assert_eq!(Some(n("port") as i32), h.port());
    assert_eq!(n("runTimeoutSeconds") as i32, m.run_timeout_in_seconds());
    assert_eq!(n("resumeTimeoutSeconds") as i32, m.resume_timeout_in_seconds());
    assert_eq!(n("suspendTimeoutSeconds") as i32, m.suspend_timeout_in_seconds());
    assert_eq!(n("terminateTimeoutSeconds") as i32, m.terminate_timeout_in_seconds());
    assert_eq!(n("readyTimeoutSeconds") as i32, i.ready_timeout_in_seconds());
    assert_eq!(n("validateTimeoutSeconds") as i32, i.validate_timeout_in_seconds());
    assert_eq!(c["imageName"], "ai-env-agent");
    assert_eq!(c["architecture"], "ARM_64");
    assert_eq!(c["memoryMiB"], 2048);
    assert_eq!(c["baseImage"]["name"], "al2023-1");
    assert_eq!(c["baseImage"]["version"], "1", "a string: the API's version identifier");
    assert_eq!(c["additionalOsCapabilities"], serde_json::json!([]), "plan D20: least privilege in v0");
    assert_eq!(c["logGroup"], "/aws/lambda-microvms/ai-env-agent", "the platform's own prefix (plan D21)");
    assert_eq!(c["logGroup"].as_str().unwrap().rsplit('/').next(), c["imageName"].as_str());
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
    // The real host shape: agent_request pins the endpoint suffix (S6).
    let req = agent_request("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws", &Secret::new("tok".into()), 8080).unwrap();
    let (bytes, _key) = generate_request(req).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("GET /agent HTTP/1.1\r\n"), "{text}");
    let lower = text.to_ascii_lowercase();
    assert!(lower.contains("host: bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws"), "{text}");
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
    // CloudFront in front of the site answers 403 to an HTTP/1.1 request without a User-Agent (30 Sep 2026), so the
    // request names one: a refusal after `send()` succeeded would be the site's policy, not a TLS failure.
    let r = client.get("https://www.amazontrust.com/repository/").header("user-agent", "ai-env-tests").send().await.unwrap();
    eprintln!("tls_live_amazontrust: HTTP {} {:?} (TLS 1.3 under Amazon Root CA 1–4)", r.status(), r.version());
    assert!(r.status().is_success(), "{} (the handshake succeeded; the site refused the request)", r.status());
}

fn spec(token: &str) -> RunSpec {
    RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        execution_role_arn: None,
        ingress_connectors: vec![],
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
    assert!(vm.id.starts_with("microvm-"), "{}", vm.id);
    assert_eq!(normalize_endpoint(&vm.endpoint).unwrap(), vm.endpoint, "the fake serves a pinned bare host");
    assert!(!vm.endpoint.starts_with(&vm.id), "the endpoint label is not the VM id (S3 live)");
    assert_eq!(vm.ingress, vec![managed_connector_arn("HTTP_INGRESS")], "the platform default is echoed");
    let again = api.run(&spec("t1")).await.unwrap();
    assert_eq!(again.id, vm.id, "same client_token → same VM (idempotent RunMicrovm)");
    let e = api.suspend(&vm.id).await.unwrap_err();
    assert!(matches!(e, BridgeError::Conflict(_)), "suspend needs RUNNING: {e}");
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
    api.terminate(&vm.id).await.unwrap();
    assert_eq!(api.get(&vm.id).await.unwrap().state, VmState::Terminated, "TERMINATING, then TERMINATED on the next look");
    api.terminate(&vm.id).await.unwrap();
    let listed = api.list(Some(FAKE_IMAGE_ARN)).await.unwrap();
    assert_eq!(listed.len(), 1, "TERMINATED VMs stay listed in the fake");
    assert_eq!(listed[0].state, VmState::Terminated);
    assert_eq!(api.list(Some("other")).await.unwrap().len(), 0);
    assert!(matches!(api.get("microvm-nope").await.unwrap_err(), BridgeError::VmNotFound(_)));
    assert_eq!(api.list_managed_images().await.unwrap()[0].arn, "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1");
    let calls = api.calls();
    assert_eq!(calls[0], Call::Run { client_token: "t1".into() });
    assert_eq!(calls[1], Call::Run { client_token: "t1".into() });
    assert_eq!(calls[2], Call::Suspend(vm.id.clone()));
    assert!(calls.contains(&Call::Token { id: vm.id.clone(), minutes: 60, port: 8080 }));
    assert!(calls.contains(&Call::List(Some(FAKE_IMAGE_ARN.to_string()))));
    assert_eq!(*calls.last().unwrap(), Call::ListImages);
    assert_eq!(api.run_specs().len(), 1, "the idempotent replay created nothing");
}

#[tokio::test]
async fn fake_api_fail_next() {
    let api = FakeMicrovmApi::new();
    api.fail_next(BridgeError::Quota("memory".into()));
    let e = api.run(&spec("t")).await.unwrap_err();
    let c: ai_env_cli::errors::CliError = e.into();
    assert_eq!(c.exit_code(), 7);
    assert!(api.run(&spec("t")).await.is_ok(), "failure is one-shot");
}

#[tokio::test]
async fn fake_run_can_fail_after_creating_the_vm() {
    let api = FakeMicrovmApi::new();
    api.fail_on("run", BridgeError::Ambiguous { op: "run_microvm", message: "timeout".into() }, true);
    let e = api.run(&spec("t")).await.unwrap_err();
    assert!(matches!(e, BridgeError::Ambiguous { .. }), "{e}");
    assert_eq!(api.list(None).await.unwrap().len(), 1, "the request reached the service");
    let vm = api.run(&spec("t")).await.unwrap();
    assert_eq!(api.list(None).await.unwrap().len(), 1, "the retry with the same token finds it");
    assert_eq!(vm.state, VmState::Pending);
}

#[tokio::test]
async fn fake_endpoint_checks_port_vm_and_expiry() {
    let api = FakeMicrovmApi::new();
    api.set_auto_advance(true);
    let payload = RunHookPayload::new(&Secret::new("s".repeat(64)), "mike@host", "2026-09-29T10:00:00.123Z").to_json().unwrap();
    let vm = api.run(&RunSpec { run_hook_payload: payload, ..spec("t") }).await.unwrap();
    api.get(&vm.id).await.unwrap();
    let tok = api.create_auth_token(&vm.id, 5, 8080).await.unwrap();
    let ok = api.get_health(&vm.endpoint, &tok, 8080).await.unwrap();
    assert_eq!(ok.status, 200);
    let h = ok.health.unwrap();
    assert_eq!(h.owner.as_deref(), Some("mike@host"));
    assert_eq!(h.created.as_deref(), Some("2026-09-29T10:00:00.123Z"));
    assert_eq!(h.microvm_id.as_deref(), Some(vm.id.as_str()));
    let wrong_port = api.get_health(&vm.endpoint, &tok, 9000).await.unwrap();
    assert_eq!((wrong_port.status, wrong_port.proxy_error.as_deref()), (403, Some("UNAUTHORIZED")));
    let other = api.create_auth_token(&vm.id, 5, 8081).await.unwrap();
    assert_eq!(api.get_health(&vm.endpoint, &other, 8080).await.unwrap().status, 403, "a Port(8081) token on 8080");
    api.script_health(&vm.id, &[502, 429]);
    assert_eq!(api.get_health(&vm.endpoint, &tok, 8080).await.unwrap().status, 502);
    let throttled = api.get_health(&vm.endpoint, &tok, 8080).await.unwrap();
    assert_eq!((throttled.status, throttled.retry_after_s), (429, Some(1)));
    assert_eq!(api.get_health(&vm.endpoint, &tok, 8080).await.unwrap().status, 200);
    api.suspend(&vm.id).await.unwrap();
    assert_eq!(api.get_health(&vm.endpoint, &tok, 8080).await.unwrap().status, 200, "auto-resume on the request");
    assert_eq!(api.get(&vm.id).await.unwrap().state, VmState::Running);
    api.expire_tokens();
    assert_eq!(api.get_health(&vm.endpoint, &tok, 8080).await.unwrap().status, 403, "expired");
    assert!(matches!(api.create_shell_token(&vm.id, 15).await.unwrap_err(), BridgeError::Validation(_)), "no SHELL_INGRESS");
}

// ---- S4: the SDK client, request shape, managed connectors (offline) -----------------

/// Static credentials of the right shape, built at run time (no credential-shaped literal).
fn test_creds() -> RuntimeCreds {
    let id = format!("AKIA{}", "TEST".repeat(4));
    let secret = format!("{}{}", "aB1/".repeat(9), "cD2+");
    RuntimeCreds::Static(Credentials::new(id, secret, None, None, "ai-env-test"))
}

/// Every `RunSpec` field reaches `RunMicrovmInput` (inspected offline through the
/// fluent builder; nothing is sent).
#[tokio::test]
async fn run_request_sets_every_field() {
    let cfg = sdk_config_for(&test_creds()).await;
    let client = aws_sdk_lambdamicrovms::Client::new(&cfg);
    let payload = RunHookPayload::new(&Secret::new("s".repeat(64)), "mike@host", "2026-09-29T10:00:00.123Z").to_json().unwrap();
    let role = "arn:aws:iam::123456789012:role/ai-env-agent-exec".to_string();
    let egress = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress".to_string();
    let spec = RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "3.0".into(),
        execution_role_arn: Some(role.clone()),
        ingress_connectors: vec![managed_connector_arn("HTTP_INGRESS"), managed_connector_arn("SHELL_INGRESS")],
        egress_connectors: vec![egress.clone()],
        idle: IdleSpec { max_idle_s: 600, suspended_s: 1800, auto_resume: false },
        max_duration_s: 3600,
        run_hook_payload: payload.clone(),
        client_token: "01926f2e-0000-7000-8000-00000000c0de".into(),
    };
    let req = run_request(&client, &spec).unwrap();
    let input = req.as_input();
    assert_eq!(input.get_image_identifier().as_deref(), Some(FAKE_IMAGE_ARN));
    assert_eq!(input.get_image_version().as_deref(), Some("3.0"));
    assert_eq!(input.get_execution_role_arn().as_deref(), Some(role.as_str()));
    let idle = input.get_idle_policy().as_ref().expect("the idle policy is always passed (plan D8)");
    assert_eq!((idle.max_idle_duration_seconds(), idle.suspended_duration_seconds(), idle.auto_resume_enabled()), (600, 1800, false));
    assert_eq!(*input.get_maximum_duration_in_seconds(), Some(3600));
    assert_eq!(input.get_run_hook_payload().as_deref(), Some(payload.as_str()));
    assert_eq!(input.get_client_token().as_deref(), Some("01926f2e-0000-7000-8000-00000000c0de"));
    assert_eq!(input.get_ingress_network_connectors().as_deref(), Some([managed_connector_arn("HTTP_INGRESS"), managed_connector_arn("SHELL_INGRESS")].as_slice()));
    assert_eq!(input.get_egress_network_connectors().as_deref(), Some([egress].as_slice()));
    assert_eq!(*input.get_logging(), None, "logging is run-level and never passed (plan §3)");

    let defaults = RunSpec { execution_role_arn: None, ingress_connectors: vec![], egress_connectors: vec![], ..spec };
    let input = run_request(&client, &defaults).unwrap();
    let input = input.as_input();
    assert_eq!(*input.get_execution_role_arn(), None);
    assert_eq!(*input.get_ingress_network_connectors(), None, "empty = the platform default, never sent as []");
    assert_eq!(*input.get_egress_network_connectors(), None, "egress internet = the platform default (plan D10)");
}

/// The managed INTERNET_EGRESS connector the Pulumi program grants (infra/policies.ts)
/// is the one `managed_connector_arn` names, and the managed-connector wildcard of the
/// runtime policy covers every managed connector the bridge passes.
#[test]
fn managed_connector_arn_matches_infra_policies() {
    let ts = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/policies.ts")).unwrap();
    let after = ts.split("function internetEgressConnectorArn(").nth(1).expect("infra/policies.ts defines internetEgressConnectorArn");
    let template = after.split('`').nth(1).expect("internetEgressConnectorArn returns a template literal");
    assert_eq!(template.replace("${region}", "eu-central-1"), managed_connector_arn("INTERNET_EGRESS"));
    let wildcard = "arn:aws:lambda:${n.region}:aws:network-connector:*";
    assert!(ts.contains(wildcard), "connectorArns grants the managed connectors by wildcard");
    let prefix = wildcard.replace("${n.region}", "eu-central-1");
    let prefix = prefix.trim_end_matches('*');
    for name in ["HTTP_INGRESS", "SHELL_INGRESS", "INTERNET_EGRESS"] {
        assert!(managed_connector_arn(name).starts_with(prefix), "{name}");
    }
}

/// `tls::reqwest_client()` refuses plaintext before any connection (https
/// only): a `http://` redirector is never dialled, so neither is its target.
/// The redirect policy itself (a 302 is never followed) is unit-tested in
/// `bridge::tls` over loopback http.
#[tokio::test]
async fn reqwest_client_refuses_plaintext_before_connecting() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let redirector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = redirector.local_addr().unwrap();
    let dialled = std::sync::Arc::new(AtomicUsize::new(0));
    let seen = dialled.clone();
    tokio::spawn(async move {
        while let Ok((_s, _)) = redirector.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });
    let token = format!("probe-token-{}", "7".repeat(20));
    let result = tls::reqwest_client().unwrap().get(format!("http://{addr}/health")).header("x-aws-proxy-auth", token).send().await;
    assert!(result.is_err(), "a plaintext request must be refused");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(dialled.load(Ordering::SeqCst), 0, "the plaintext endpoint was dialled");
}

/// Profile mode never writes the access key id to `logs/ai-env.log`: aws-config
/// logs the resolved `Credentials` with `{:?}` (access key id, and the account
/// id after an assume-role hop) at INFO under `aws_config::profile::credentials`;
/// `bridge::logging` holds `aws_config` to ERROR, so no such event arrives (the
/// scrubber's AKIA rule is a second layer). Offline: in-memory profile files, static keys.
#[tokio::test]
#[allow(deprecated)] // aws-config 1.12 re-exports ProfileFiles under deprecated aliases (plan D21)
async fn profile_mode_never_logs_the_access_key_id() {
    use aws_config::profile::profile_file::{ProfileFileKind, ProfileFiles};
    use aws_config::profile::ProfileFileCredentialsProvider;
    use aws_sdk_lambdamicrovms::config::ProvideCredentials;
    let id = format!("AKIA{}", "LOGS".repeat(4));
    let secret = format!("{}{}", "hJ5+".repeat(9), "kL6/");
    let files = ProfileFiles::builder()
        .with_contents(ProfileFileKind::Config, "[profile ai-env-logs]\nregion = eu-central-1\n")
        .with_contents(ProfileFileKind::Credentials, format!("[ai-env-logs]\naws_access_key_id = {id}\naws_secret_access_key = {secret}\n"))
        .build();
    let provider = ProfileFileCredentialsProvider::builder().profile_files(files).profile_name("ai-env-logs").build();
    let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let _default = tracing::subscriber::set_default(ai_env_cli::bridge::logging::build_subscriber_for_test(sink.clone(), ""));
    let creds = provider.provide_credentials().await.unwrap();
    assert_eq!(creds.access_key_id(), id);
    let log = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
    // The sink scrubs AKIA-shaped ids anyway, so the cap itself is what is asserted: no aws_config event below ERROR.
    assert!(!log.contains("aws_config"), "an aws_config event reached the log:\n{}", log.replace(&id[4..], "<id>"));
    assert!(!log.contains(&id[4..]) && !log.contains(&secret), "the key id reached the log");
}

// ---- S4: read-only live checks (this session's account, eu-central-1, nothing created) -----

/// Any standalone 12-digit run (an account id, as in `arn:aws:…:<account>:…`) other
/// than the documentation one, masked for test output; digits inside a uuid or a
/// longer token are kept.
fn no_account(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut digits = String::new();
    let mut glued = false;
    let flush = |digits: &mut String, out: &mut String, glued: bool, next: Option<char>| {
        let standalone = !glued && !next.is_some_and(|c| c == '-' || c.is_ascii_alphanumeric());
        if standalone && digits.len() == 12 && digits != "123456789012" {
            out.push_str("<account>");
        } else {
            out.push_str(digits);
        }
        digits.clear();
    };
    let mut prev: Option<char> = None;
    for c in text.chars() {
        if c.is_ascii_digit() {
            if digits.is_empty() {
                glued = prev.is_some_and(|p| p == '-' || p.is_ascii_alphanumeric());
            }
            digits.push(c);
        } else {
            flush(&mut digits, &mut out, glued, Some(c));
            out.push(c);
        }
        prev = Some(c);
    }
    flush(&mut digits, &mut out, glued, None);
    out
}

#[test]
fn no_account_masks_only_account_ids() {
    let acct = "9".repeat(12);
    assert_eq!(no_account(&format!("arn:aws:iam::{acct}:user/x")), "arn:aws:iam::<account>:user/x");
    assert_eq!(no_account(&format!("account {acct}.")), "account <account>.");
    assert_eq!(no_account("arn:aws:lambda:eu-central-1:123456789012:x"), "arn:aws:lambda:eu-central-1:123456789012:x");
    assert_eq!(no_account("microvm-00000000-0000-4000-8000-000000000000"), "microvm-00000000-0000-4000-8000-000000000000");
    assert_eq!(no_account(&format!("x{acct}")), format!("x{acct}"));
}

/// GET /health of a host no VM owns, with a dummy token: the proxy answers 403 with
/// `x-aws-proxy-error`, which proves the rustls handshake under the pinned Amazon
/// roots and TLS 1.3 against the real endpoint domain. No credentials involved.
#[tokio::test]
#[ignore = "live, read-only: AI_ENV_AWS_TESTS=1 cargo test --test aws -- --ignored readonly_"]
async fn readonly_endpoint_tls_unauthenticated_403() {
    if !live() {
        return;
    }
    let ep = HttpsEndpoint::new().unwrap();
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(TOKEN_HEADER.to_string(), Secret::new(format!("probe-{}", "0".repeat(26))));
    let token = AuthToken { headers, port: 8080, expires_at_unix: 0 };
    let r = ep.get_health("probe-nonexistent.lambda-microvm.eu-central-1.on.aws", &token, 8080).await.unwrap();
    eprintln!("readonly_endpoint_tls_unauthenticated_403: HTTP {} x-aws-proxy-error={:?} body={:?}", r.status, r.proxy_error, no_account(&r.body));
    assert_eq!(r.status, 403);
    assert!(r.proxy_error.is_some(), "the proxy names why it refused");
}

#[tokio::test]
#[ignore = "live, read-only: AI_ENV_AWS_TESTS=1 cargo test --test aws -- --ignored readonly_"]
async fn readonly_control_plane_list_managed_images() {
    if !live() {
        return;
    }
    let api = connect(&RuntimeCreds::DefaultChainForReadOnlyTests).await;
    let images = api.list_managed_images().await.unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
    let arns: Vec<&str> = images.iter().map(|i| i.arn.as_str()).collect();
    eprintln!("readonly_control_plane_list_managed_images: {} image(s): {:?}", arns.len(), arns);
    assert!(arns.iter().any(|a| a.ends_with(":microvm-image:al2023-1")), "{arns:?}");
}

#[tokio::test]
#[ignore = "live, read-only: AI_ENV_AWS_TESTS=1 cargo test --test aws -- --ignored readonly_"]
async fn readonly_list_microvms_with_image_filter() {
    if !live() {
        return;
    }
    let api = connect(&RuntimeCreds::DefaultChainForReadOnlyTests).await;
    let arn = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-probe-nonexistent";
    match api.list(Some(arn)).await {
        Ok(vms) => {
            eprintln!("readonly_list_microvms_with_image_filter: Ok({} VMs)", vms.len());
            assert!(vms.is_empty(), "a made-up image has no VMs");
        }
        Err(e @ (BridgeError::AccessDenied(_) | BridgeError::Validation(_))) => {
            eprintln!("readonly_list_microvms_with_image_filter: refused: {}", no_account(&e.to_string()));
        }
        Err(e) => panic!("readonly_list_microvms_with_image_filter: unexpected: {}", no_account(&e.to_string())),
    }
}

#[tokio::test]
#[ignore = "live, read-only: AI_ENV_AWS_TESTS=1 cargo test --test aws -- --ignored readonly_"]
async fn readonly_get_unknown_microvm_is_vm_not_found_exit_8() {
    if !live() {
        return;
    }
    let api = connect(&RuntimeCreds::DefaultChainForReadOnlyTests).await;
    let e = api.get("microvm-00000000-0000-4000-8000-000000000000").await.unwrap_err();
    eprintln!("readonly_get_unknown_microvm_is_vm_not_found_exit_8: {}", no_account(&e.to_string()));
    assert!(matches!(e, BridgeError::VmNotFound(_)), "{}", no_account(&e.to_string()));
    assert_eq!(CliError::from(e).exit_code(), 8);
}

// ---- S4: the live lifecycle suite (part B: Mike's terminal, `make test-aws`) ---------------
//
// Each test runs in a temp bridge root holding COPIES of the real bridge.toml,
// credentials/aws.env (ciphertext) and state/infra.toml, so every row it writes
// stays there; the keystore is the real one (read-only). The runtime key is
// unsealed once per test process (one Touch ID). `VmGuard` terminates exactly
// the VMs a test started (and a pending row's VM it can adopt); any other VM
// of the image is never touched.

use ai_env_cli::bridge::config::{BridgeConfig, Paths};
use ai_env_cli::bridge::vm::run::{self as vmrun, Poll, RunFlags, RunPlan, Selected};

static LIVE_CREDS: std::sync::OnceLock<RuntimeCreds> = std::sync::OnceLock::new();

struct Live {
    _dir: tempfile::TempDir,
    paths: Paths,
    cfg: BridgeConfig,
    creds: RuntimeCreds,
}

fn live_world() -> Live {
    let real = Paths::resolve().expect("the real bridge root");
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
    std::fs::copy(&real.config, &paths.config).unwrap_or_else(|e| panic!("{}: {e} (run make infra-status WRITE=1)", real.config.display()));
    for (from, to) in [(real.aws_env(), paths.aws_env()), (real.infra_state(), paths.infra_state())] {
        if from.exists() {
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(&from, &to).unwrap();
        }
    }
    let cfg = BridgeConfig::load(&paths).unwrap().expect("bridge.toml");
    if LIVE_CREDS.get().is_none() {
        announce_touch_id("the test process", "its runtime key, once for every live test it runs");
    }
    let creds = LIVE_CREDS
        .get_or_init(|| {
            let store = ai_env_cli::store::Keystore::resolve(None).expect("keystore");
            ai_env_cli::bridge::vm::client::runtime_credentials(&store, &paths, &cfg).unwrap_or_else(|e| panic!("runtime credentials: {e}"))
        })
        .clone();
    Live { _dir: dir, paths, cfg, creds }
}

/// Terminates, on drop, every VM a test registered (on its own runtime and thread).
struct VmGuard {
    creds: RuntimeCreds,
    paths: Paths,
    ids: std::sync::Mutex<Vec<String>>,
}

impl VmGuard {
    fn new(live: &Live) -> VmGuard {
        VmGuard { creds: live.creds.clone(), paths: live.paths.clone(), ids: std::sync::Mutex::new(Vec::new()) }
    }

    fn add(&self, id: &str) {
        self.ids.lock().unwrap().push(id.to_string());
    }
}

impl Drop for VmGuard {
    fn drop(&mut self) {
        let ids = std::mem::take(&mut *self.ids.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        if ids.is_empty() {
            return;
        }
        let (creds, paths) = (self.creds.clone(), self.paths.clone());
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            // Every VM first, then what happened: with the terminal gone (SIGHUP) a print panics, and must not cost a VM.
            let said = rt.block_on(async {
                let api = connect(&creds).await;
                let mut said = Vec::new();
                for id in ids {
                    said.push(match vmrun::terminate_and_record(&api, &paths, &id, "test", Some(Poll::SETTLE)).await {
                        Ok(_) => format!("guard: terminated {id}"),
                        Err(e) => format!("guard: could not terminate {id}: {} — run: ai-env vm terminate {id} --yes (the test's row lived in a temp root)", no_account(&e.to_string())),
                    });
                }
                said
            });
            for line in said {
                eprintln!("{line}");
            }
        })
        .join();
    }
}

fn test_plan(live: &Live, idle_s: Option<u32>) -> RunPlan {
    let flags = RunFlags { max_duration_s: Some(900), idle_s, label: Some("test".into()), purpose: "test", imply_internet: true, ..RunFlags::default() };
    RunPlan::from_cfg(&live.cfg, &flags).unwrap_or_else(|e| panic!("run plan: {e}"))
}

/// Start one VM through SELECT_VM; every VM that may have started is handed to the guard.
async fn start(api: &ai_env_cli::bridge::vm::client::SdkMicrovmApi, ep: &HttpsEndpoint, live: &Live, guard: &VmGuard, plan: &RunPlan) -> (ai_env_cli::bridge::vm::registry::VmRow, ai_env_cli::bridge::api::VmInfo, u64) {
    let since = ai_env_cli::wire::time::unix_now();
    match vmrun::select_vm_detailed(api, &live.paths, plan, Poll::RUNNING).await {
        Ok(Selected::Started { row, vm, running_ms, .. }) => {
            guard.add(&vm.id);
            (row, vm, running_ms)
        }
        Ok(Selected::Reused { vm, .. }) => panic!("a test VM was reused: {}", vm.id),
        Err(f) => {
            if let Some(id) = &f.started {
                guard.add(id);
            }
            if let Some(p) = &f.kept_pending {
                match vmrun::adopt_after_ambiguous_for(api, ep, &live.paths, p, since, Poll::RUNNING, "test").await {
                    Ok(vmrun::Adoption::Adopted(id)) => guard.add(&id),
                    Ok(vmrun::Adoption::Unresolved(ids)) => eprintln!("start: VMs that may be this test's could not be asked: {} — check with ai-env vm gc; ai-env vm terminate <id> --yes", ids.join(", ")),
                    Ok(vmrun::Adoption::NoMatch) => eprintln!("start: no VM of this test's ambiguous run is visible"),
                    // The S5 egress gate rejected the adopted VM but could not terminate it: the guard tries again.
                    Err(BridgeError::EgressMismatch(m)) if !m.terminated => {
                        eprintln!("start: the ambiguous run's VM {} failed the egress gate and is not confirmed terminated", m.id);
                        guard.add(&m.id);
                    }
                    Err(e) => eprintln!("start: the adoption sweep failed: {}", no_account(&e.to_string())),
                }
            }
            panic!("start: {}", no_account(&f.error.to_string()));
        }
    }
}

#[tokio::test]
#[ignore = "live, starts a MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_vm_lifecycle() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let plan = test_plan(&live, None);
    let (row, vm, running_ms) = start(&api, &ep, &live, &guard, &plan).await;
    eprintln!("live_vm_lifecycle: {} RUNNING after {running_ms} ms; endpoint {}; ingress {:?}; egress {:?}", vm.id, vm.endpoint, vm.ingress, vm.egress);
    assert_eq!(vm.max_duration_s, 900);
    assert_eq!(vm.idle, Some(plan.idle), "the idle policy is echoed as sent");
    let t = std::time::Instant::now();
    let (h, stats) = ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
    eprintln!("live_vm_lifecycle: /health after {} ms ({} attempts): {h:?}", t.elapsed().as_millis(), stats.attempts);
    assert!(h.run_hook_seen);
    assert_eq!(h.owner.as_deref(), Some(row.owner.as_str()));
    assert_eq!(h.created.as_deref(), Some(row.created.as_str()));
    assert_eq!(h.microvm_id.as_deref(), Some(vm.id.as_str()));
    let listed = api.list(Some(&plan.image_arn)).await.unwrap();
    assert!(listed.iter().any(|s| s.id == vm.id), "ListMicrovms shows the VM");
    let t = std::time::Instant::now();
    let end = vmrun::terminate_and_record(&api, &live.paths, &vm.id, "test", Some(Poll::SETTLE)).await.unwrap();
    eprintln!("live_vm_lifecycle: TERMINATED after {} ms ({:?})", t.elapsed().as_millis(), end.map(|v| v.state));
    let after = api.list(Some(&plan.image_arn)).await.unwrap();
    eprintln!("live_vm_lifecycle: ListMicrovms keeps TERMINATED VMs: {}", after.iter().any(|s| s.id == vm.id));
}

#[tokio::test]
#[ignore = "live, starts a MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_vm_token_scoping() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (_, vm, _) = start(&api, &ep, &live, &guard, &test_plan(&live, None)).await;
    ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap();
    let t8080 = api.create_auth_token(&vm.id, 5, 8080).await.unwrap();
    assert_eq!(t8080.headers.keys().collect::<Vec<_>>(), vec![TOKEN_HEADER], "the token map has exactly the X-aws-proxy-auth key");
    assert_eq!(ep.get_health(&vm.endpoint, &t8080, 8080).await.unwrap().status, 200);
    let wrong_header = ep.get_health(&vm.endpoint, &t8080, 9000).await.unwrap();
    eprintln!("live_vm_token_scoping: Port(8080) token, header port 9000 → HTTP {} x-aws-proxy-error={:?}", wrong_header.status, wrong_header.proxy_error);
    assert!(matches!(wrong_header.status, 401 | 403), "{}", wrong_header.status);
    assert!(wrong_header.proxy_error.is_some(), "the proxy names why it refused");
    let t8081 = api.create_auth_token(&vm.id, 5, 8081).await.unwrap();
    let wrong_scope = ep.get_health(&vm.endpoint, &t8081, 8080).await.unwrap();
    eprintln!("live_vm_token_scoping: Port(8081) token on 8080 → HTTP {} x-aws-proxy-error={:?}", wrong_scope.status, wrong_scope.proxy_error);
    assert!(matches!(wrong_scope.status, 401 | 403), "{}", wrong_scope.status);
    assert!(wrong_scope.proxy_error.is_some(), "the proxy names why it refused");
}

#[tokio::test]
#[ignore = "live, starts a MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_vm_suspend_resume() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (_, vm, _) = start(&api, &ep, &live, &guard, &test_plan(&live, None)).await;
    let t = std::time::Instant::now();
    api.suspend(&vm.id).await.unwrap();
    vmrun::wait_for_state(&api, &vm.id, &VmState::Suspended, Poll::SETTLE).await.unwrap();
    eprintln!("live_vm_suspend_resume: SUSPENDED after {} ms", t.elapsed().as_millis());
    let t = std::time::Instant::now();
    api.resume(&vm.id).await.unwrap();
    vmrun::wait_for_state(&api, &vm.id, &VmState::Running, Poll::SETTLE).await.unwrap();
    eprintln!("live_vm_suspend_resume: RUNNING again after {} ms", t.elapsed().as_millis());
    let (h, _) = ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap();
    assert!(h.run_hook_seen, "the process survived the suspend");
}

/// T4.2's expiry case: a 5-minute token used after 6 minutes on a VM whose idle
/// limit (600 s) outlasts the wait, called straight through the endpoint (no
/// re-mint). Opt-in: `make test-aws SLOW=1`.
#[tokio::test]
#[ignore = "live, 6+ minutes: AI_ENV_AWS_TESTS=1 AI_ENV_AWS_SLOW=1 (make test-aws SLOW=1)"]
async fn live_vm_token_expiry() {
    if !live() {
        return;
    }
    if std::env::var("AI_ENV_AWS_SLOW").as_deref() != Ok("1") {
        eprintln!("skipped: set AI_ENV_AWS_SLOW=1 (make test-aws SLOW=1) for the 6-minute token-expiry test");
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (_, vm, _) = start(&api, &ep, &live, &guard, &test_plan(&live, Some(600))).await;
    ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap();
    let token = api.create_auth_token(&vm.id, 5, 8080).await.unwrap();
    assert_eq!(ep.get_health(&vm.endpoint, &token, 8080).await.unwrap().status, 200);
    tokio::time::sleep(std::time::Duration::from_secs(370)).await;
    let stale = ep.get_health(&vm.endpoint, &token, 8080).await.unwrap();
    eprintln!("live_vm_token_expiry: 5-minute token after 370 s → HTTP {} x-aws-proxy-error={:?}", stale.status, stale.proxy_error);
    assert!(matches!(stale.status, 401 | 403), "{}", stale.status);
}

// ---- S5: the live egress tests (part B: Mike's terminal, `make test-egress`) ---------------
//
// Each test starts its own `--egress vpc --shell` VM (the stack's connector, 900 s) in a
// temp copy of the bridge root, runs the `ai-env egress check` script — or the cases it
// needs — through the platform shell and judges it as the command does; nothing is
// recorded in egress-verified.toml (the markers are the VM's own word; squid's log is
// read where it matters). The transcript is parsed, never printed. The tests run one at a
// time (`egress_serial`): each holds a VM, and [vm].max_concurrent is small.
// `live_egress_extra_and_removal` edits the proxy's extras through the operator's real
// bridge root, so it shares `state/egress.lock` and the audit with every other command.
// Like the command, the tests judge github.com by the effective allowlist, read after the
// cases ran (`live_allowlisted`: SSM's lists, a lighter read than the command's proved one):
// while an operator allows it for a workspace, its case is recorded, not judged.

use ai_env_cli::bridge::egress::check::{self, Judgement, Markers, Verdict};
use ai_env_cli::bridge::egress::{ConnectorAlias, ExpectedEcho};
use ai_env_cli::bridge::lab::VmKnobs;
use ai_env_cli::bridge::s3::S3Target;
use ai_env_cli::bridge::transport::ShellAuth;
use ai_env_cli::bridge::vm::client::SdkMicrovmApi;
use ai_env_cli::bridge::vm::health::{read_health, Backoff};
use ai_env_cli::bridge::vm::shell::run_script;

/// Gate for the live egress tests: they need both `AI_ENV_AWS_TESTS=1` and `AI_ENV_EGRESS_TESTS=1`.
fn live_egress() -> bool {
    if std::env::var("AI_ENV_AWS_TESTS").as_deref() == Ok("1") && std::env::var("AI_ENV_EGRESS_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_AWS_TESTS=1 and AI_ENV_EGRESS_TESTS=1 to run the live egress tests (make test-egress)");
    false
}

/// `body` on its own current-thread runtime, one live egress test at a time.
fn egress_serial(body: impl std::future::Future<Output = ()>) {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(body);
}

/// `vm run --egress vpc --shell` for a test (900 s, idle from bridge.toml).
fn egress_plan(live: &Live) -> RunPlan {
    let flags = RunFlags { max_duration_s: Some(900), label: Some("test-egress".into()), egress: Some(vmrun::Egress::Vpc), shell: true, purpose: "test", ..RunFlags::default() };
    RunPlan::from_cfg(&live.cfg, &flags).unwrap_or_else(|e| panic!("egress run plan: {e} (make infra-status WRITE=1 records [aws].egress_connector_arn)"))
}

/// What a scripted run through the platform shell returned: the parsed
/// markers, the run's nonce, and when the script was sent and came back
/// (the squid log's window).
struct Shelled {
    markers: Markers,
    nonce: String,
    started_s: u64,
    ended_s: u64,
}

/// The VM booted (its /health answers), then the named cases through the
/// platform shell, in one frame (`check::render_cases`: never a case that asks
/// the transcripts bucket — the full check, [`shell_check`], runs those).
async fn shell_cases(api: &SdkMicrovmApi, ep: &HttpsEndpoint, live: &Live, id: &str, names: &[&str]) -> Shelled {
    read_health(api, ep, &live.paths, id, Backoff::HEALTH).await.unwrap_or_else(|e| panic!("/health of {id}: {}", no_account(&e.to_string())));
    let nonce = check::new_nonce();
    let script = check::render_cases(&nonce, &check::proxy_ip(&live.cfg, &live.paths), names);
    let started_s = ai_env_cli::wire::time::unix_now();
    let out = run_script(api, id, &script, check::script_budget(names.len()), ShellAuth::Header).await.unwrap_or_else(|e| panic!("the scripted shell on {id}: {}", no_account(&e.to_string())));
    let ended_s = ai_env_cli::wire::time::unix_now();
    let markers = check::parse_markers(&out, &nonce).unwrap_or_else(|e| panic!("the transcript of {id}: {e}"));
    Shelled { markers, nonce, started_s, ended_s }
}

/// The VM booted (its /health answers), then every case of `ai-env egress
/// check` through the platform shell, as the command runs them: the script for
/// the transcripts bucket state/infra.toml records (after the S9 deploy and
/// `make infra-status WRITE=1`), the presigned URLs it reads typed only once
/// it asks (`check::run_check_script`).
async fn shell_check(api: &SdkMicrovmApi, ep: &HttpsEndpoint, live: &Live, id: &str) -> Shelled {
    read_health(api, ep, &live.paths, id, Backoff::HEALTH).await.unwrap_or_else(|e| panic!("/health of {id}: {}", no_account(&e.to_string())));
    let bucket = S3Target::resolve(&live.paths, &VmKnobs::default()).unwrap_or_else(|e| panic!("the transcripts bucket: {}", no_account(&e.to_string())));
    let nonce = check::new_nonce();
    let script = check::render_script_with(&nonce, &check::proxy_ip(&live.cfg, &live.paths), &check::S3Probe::of(&bucket));
    let started_s = ai_env_cli::wire::time::unix_now();
    let out = check::run_check_script(api, id, &script, &nonce, Some(&bucket), check::script_budget(check::CASES.len()), ShellAuth::Header)
        .await
        .unwrap_or_else(|e| panic!("the scripted shell on {id}: {}", no_account(&e.to_string())));
    let ended_s = ai_env_cli::wire::time::unix_now();
    let markers = check::parse_markers(&out, &nonce).unwrap_or_else(|e| panic!("the transcript of {id}: {e}"));
    Shelled { markers, nonce, started_s, ended_s }
}

/// What the S3 cases are judged by besides their markers, as the command
/// gathers it before the script runs: whether the VM runs with an execution
/// role (its plan's, or its echo of one), and the Mac's anonymous GET of the
/// front object.
async fn live_s3_facts(plan: &RunPlan, vm: &ai_env_cli::bridge::api::VmInfo) -> check::S3Facts {
    check::S3Facts { has_role: plan.execution_role_arn.is_some() || vm.execution_role_arn.is_some(), front: check::front_object().await }
}

/// The hosts `check::judge_with` records, not judges: those of `check::ALLOWLISTABLE` on the
/// effective allowlist as SSM holds it now (`check::live_allowlist`, the operator's aws CLI).
fn live_allowlisted() -> std::collections::BTreeSet<String> {
    check::allowlisted_hosts(&check::live_allowlist().unwrap_or_else(|e| panic!("the live allowlist: {}", no_account(&e))))
}

fn show(test: &str, id: &str, j: &Judgement) {
    eprintln!("{test}: {id}, script finished: {}, dns {}", j.finished, j.dns);
    for c in &j.cases {
        eprintln!("  {:<9} {:<19} {}", c.verdict.as_str(), c.name, c.reason);
    }
}

#[test]
#[ignore = "live, starts a vpc MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 make test-egress"]
fn live_egress_direct_closed() {
    if !live_egress() {
        return;
    }
    egress_serial(async {
        let live = live_world();
        let guard = VmGuard::new(&live);
        let api = connect(&live.creds).await;
        let ep = HttpsEndpoint::new().unwrap();
        let plan = egress_plan(&live);
        let (_, vm, _) = start(&api, &ep, &live, &guard, &plan).await;
        let s3 = live_s3_facts(&plan, &vm).await;
        let m = shell_check(&api, &ep, &live, &vm.id).await.markers;
        let j = check::judge_with(&m, &live_allowlisted(), &s3);
        show("live_egress_direct_closed", &vm.id, &j);
        assert!(j.finished, "the script did not finish");
        // Direct egress (name, IPv4 on 443 and 80, IPv6), every DNS path and the proxy's other ports closed (nothing
        // connected) — counted only because `allowed` passed first and last on the same VM.
        for c in j.cases.iter().filter(|c| matches!(c.group, "direct" | "dns" | "other") || check::ALLOWED_CASES.contains(&c.name)) {
            assert_ne!(c.verdict, Verdict::Fail, "{}: {}", c.name, c.reason);
        }
    });
}

#[test]
#[ignore = "live, starts a vpc MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 make test-egress"]
fn live_egress_proxy_allowlist() {
    if !live_egress() {
        return;
    }
    egress_serial(async {
        let live = live_world();
        let guard = VmGuard::new(&live);
        let api = connect(&live.creds).await;
        let ep = HttpsEndpoint::new().unwrap();
        let plan = egress_plan(&live);
        let (_, vm, _) = start(&api, &ep, &live, &guard, &plan).await;
        let s3 = live_s3_facts(&plan, &vm).await;
        let run = shell_check(&api, &ep, &live, &vm.id).await;
        let skip = live_allowlisted();
        let j = check::judge_with(&run.markers, &skip, &s3);
        show("live_egress_proxy_allowlist", &vm.id, &j);
        // allowed (first and last) → 401 in a tunnel; denied (the nonce host), an IP literal, CONNECT :8443,
        // github.com → the proxy's CONNECT 403; plain http :8080 → squid's 403 — but github.com is recorded, not
        // judged, exactly while it is allowlisted.
        for c in j.cases.iter().filter(|c| c.group == "proxy") {
            let allowlisted = check::ALLOWLISTABLE.iter().any(|(name, host)| *name == c.name && skip.contains(*host));
            assert_eq!(c.verdict, if allowlisted { Verdict::Recorded } else { Verdict::Pass }, "{}: {}", c.name, c.reason);
        }
        // squid's log in CloudWatch (the operator's aws CLI), from the run's client in its window: both tunnels,
        // a denial for every refused request, no tunnel to a refused host (an allowlisted one's aside).
        let squid = check::squid_poll(&run.nonce, run.started_s, run.ended_s, check::SQUID_LOG_BUDGET, check::SQUID_LOG_STEP, &skip).await;
        eprintln!("live_egress_proxy_allowlist: squid log: {}", no_account(&format!("{squid:?}")));
        assert!(squid.is_ok(), "{}", no_account(&format!("{squid:?}")));
    });
}

/// `ai-env egress allow ai-env-test github.com [--remove]` (the operator's aws CLI) on the
/// operator's real bridge root (its `state/egress.lock` and audit, shared with any other
/// `ai-env egress` command), killed after 300 s.
fn egress_allow(remove: bool) -> std::process::Output {
    let root = Paths::resolve().expect("the real bridge root").root;
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env"));
    c.args(["egress", "allow", "ai-env-test", "github.com"]);
    if remove {
        c.arg("--remove");
    }
    let child = c
        .env("AI_ENV_BRIDGE_DIR", root)
        .env_remove("AI_ENV_BRIDGE_CONFIG")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn ai-env");
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(300)) {
        Ok(out) => out.expect("ai-env output"),
        Err(_) => {
            let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            panic!("ai-env egress allow did not finish within 300 s");
        }
    }
}

/// The test's github.com extra: removed on drop unless `remove` already did it
/// (`make test-egress` also removes it on every exit).
struct GithubExtra {
    armed: bool,
}

impl GithubExtra {
    fn add() -> GithubExtra {
        let o = egress_allow(false);
        let extra = GithubExtra { armed: true };
        assert!(o.status.success(), "egress allow: {}", no_account(&String::from_utf8_lossy(&o.stderr)));
        extra
    }

    fn remove(&mut self) {
        let o = egress_allow(true);
        self.armed = !o.status.success();
        assert!(o.status.success(), "egress allow --remove: {}", no_account(&String::from_utf8_lossy(&o.stderr)));
    }
}

impl Drop for GithubExtra {
    fn drop(&mut self) {
        if self.armed {
            let o = egress_allow(true);
            eprintln!("guard: egress allow ai-env-test github.com --remove: exit {:?} — check with ai-env egress status", o.status.code());
        }
    }
}

#[test]
#[ignore = "live, starts a vpc MicroVM and changes the proxy's extras (Mike's account): AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 make test-egress"]
fn live_egress_extra_and_removal() {
    if !live_egress() {
        return;
    }
    egress_serial(async {
        // github.com allowlisted already: this test's own leftover (a run killed before its guard) is removed; any
        // other entry is not this test's to change, and with it the test cannot show github.com refused.
        if live_allowlisted().contains("github.com") {
            let o = egress_allow(true);
            assert!(o.status.success(), "egress allow --remove of this test's leftover: {}", no_account(&String::from_utf8_lossy(&o.stderr)));
            if live_allowlisted().contains("github.com") {
                eprintln!("live_egress_extra_and_removal: skipped: github.com is allowlisted outside this test (another workspace or the base list: ai-env egress status)");
                return;
            }
        }
        let live = live_world();
        let guard = VmGuard::new(&live);
        let api = connect(&live.creds).await;
        let ep = HttpsEndpoint::new().unwrap();
        let (_, vm, _) = start(&api, &ep, &live, &guard, &egress_plan(&live)).await;
        let github = |m: &Markers| m.get("proxy-github").cloned().expect("a proxy-github marker");
        let m = shell_cases(&api, &ep, &live, &vm.id, &["allowed", "proxy-github"]).await.markers;
        assert_eq!(m.get("allowed").map(|r| (r.code, r.hc)), Some((Some(401), Some(200))), "the VM reaches the proxy");
        assert_eq!((github(&m).hc, github(&m).t403), (Some(403), Some(true)), "github.com is denied before the test adds it (is it among the extras already? ai-env egress status)");
        // Added for the workspace ai-env-test: the tunnel opens.
        let mut extra = GithubExtra::add();
        let added = std::time::Instant::now();
        loop {
            let g = github(&shell_cases(&api, &ep, &live, &vm.id, &["proxy-github"]).await.markers);
            if g.hc == Some(200) && g.code.unwrap_or(0) != 0 {
                eprintln!("live_egress_extra_and_removal: github.com allowed {} ms after egress allow returned (HTTP {:?})", added.elapsed().as_millis(), g.code);
                break;
            }
            assert!(added.elapsed() < std::time::Duration::from_secs(30), "github.com still not allowed 30 s after egress allow: {g:?}");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        // Removed: denied again within 5 s (the reload restarts squid, so open tunnels close too).
        extra.remove();
        let removed = std::time::Instant::now();
        loop {
            let asked = removed.elapsed();
            let g = github(&shell_cases(&api, &ep, &live, &vm.id, &["proxy-github"]).await.markers);
            if g.hc == Some(403) && g.t403 == Some(true) {
                eprintln!("live_egress_extra_and_removal: github.com denied again: asked {} ms after --remove returned", asked.as_millis());
                assert!(asked <= std::time::Duration::from_secs(5), "{asked:?}");
                break;
            }
            assert!(removed.elapsed() < std::time::Duration::from_secs(5), "github.com still allowed 5 s after --remove: {g:?}");
        }
    });
}

#[test]
#[ignore = "live, starts a vpc MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 make test-egress"]
fn live_egress_after_resume() {
    if !live_egress() {
        return;
    }
    egress_serial(async {
        let live = live_world();
        let guard = VmGuard::new(&live);
        let api = connect(&live.creds).await;
        let ep = HttpsEndpoint::new().unwrap();
        let plan = egress_plan(&live);
        let (_, vm, _) = start(&api, &ep, &live, &guard, &plan).await;
        read_health(&api, &ep, &live.paths, &vm.id, Backoff::HEALTH).await.unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
        api.suspend(&vm.id).await.unwrap();
        vmrun::wait_for_state(&api, &vm.id, &VmState::Suspended, Poll::SETTLE).await.unwrap();
        api.resume(&vm.id).await.unwrap();
        let after = vmrun::wait_for_state(&api, &vm.id, &VmState::Running, Poll::SETTLE).await.unwrap();
        // The resumed VM still echoes exactly the connector.
        let expected = ExpectedEcho::for_plan(vmrun::Egress::Vpc, &plan.egress_connectors).expect("a vpc plan has its connector");
        let alias = ConnectorAlias::load(&live.paths, &plan.egress_connectors[0]);
        assert!(expected.matches(&after.egress, alias.as_ref()), "after resume {} echoes {:?}", vm.id, after.egress);
        // And egress is as closed, and the allowlist as open, as before the suspend.
        let s3 = live_s3_facts(&plan, &after).await;
        let m = shell_check(&api, &ep, &live, &vm.id).await.markers;
        let j = check::judge_with(&m, &live_allowlisted(), &s3);
        show("live_egress_after_resume", &vm.id, &j);
        assert!(j.passed(), "{:?}", j.failures());
    });
}

// ---- S6: the live agent-transport tests (part B: Mike's terminal, `make test-aws`) ---------
//
// Each starts its own MicroVM (900 s, or 4500 s for the rotation hold), runs
// commands as the agent through `/agent`, and is cleaned up by `VmGuard`.
// `live_agent_rotation` needs AI_ENV_AWS_SLOW=1 (65 minutes). Nothing runs the
// developer's `claude`: the spawns are `cat` and a `sh` line producer.

use ai_env_cli::bridge::agent::{run_spawn, spawn_channels, AgentEnv, AgentTarget, RemoteExit, RunPolicy, SpawnEvent, SpawnInput, SpawnSpec, Start};
use ai_env_cli::bridge::config::Rotation;
use ai_env_cli::bridge::transport::AgentDial;
use ai_env_cli::wire::frame::CHUNK_MAX;
use std::collections::BTreeMap;

/// `spec` as the agent through one `run_spawn`, feeding `stdin` then EOF and
/// consuming every chunk: (stdout, stderr, pid, exit).
async fn agent_exec<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, spec: SpawnSpec, stdin: Vec<u8>) -> (Vec<u8>, Vec<u8>, Option<u32>, RemoteExit) {
    let (io, c) = spawn_channels(16);
    let feed = c.input.clone();
    let feeder = tokio::spawn(async move {
        for chunk in stdin.chunks(CHUNK_MAX) {
            if feed.send(SpawnInput::Stdin(chunk.to_vec())).await.is_err() {
                return;
            }
        }
        let _ = feed.send(SpawnInput::StdinEof).await;
    });
    let mut events = c.events;
    let consumed = c.consumed.clone();
    let consumer = tokio::spawn(async move {
        let (mut out, mut err, mut pid) = (Vec::new(), Vec::new(), None);
        while let Some(ev) = events.recv().await {
            match ev {
                SpawnEvent::Started { pid: p, .. } => pid = Some(p),
                SpawnEvent::Stdout { seq, bytes } => {
                    out.extend_from_slice(&bytes);
                    consumed.stdout_done(seq);
                }
                SpawnEvent::Stderr { seq, bytes, .. } => {
                    err.extend_from_slice(&bytes);
                    consumed.stderr_done(seq);
                }
                // S10: no park in a test's own spawn.
                SpawnEvent::Note(_) | SpawnEvent::Link(_) | SpawnEvent::Exit(_) | SpawnEvent::Park(_) => {}
            }
        }
        (out, err, pid)
    });
    let outcome = run_spawn(env, Start::New(spec), io).await.unwrap_or_else(|e| panic!("run_spawn: {}", no_account(&e.to_string())));
    drop(c.input);
    drop(c.control);
    feeder.abort();
    let (out, err, pid) = consumer.await.unwrap();
    (out, err, pid, outcome.exit)
}

/// The agent target from a started VM's row (its session token).
fn agent_target(live: &Live, id: &str) -> AgentTarget {
    let row = ai_env_cli::bridge::vm::registry::read_row(&live.paths, id).unwrap().unwrap_or_else(|| panic!("no row for {id}"));
    AgentTarget::from_row(&row).unwrap_or_else(|e| panic!("agent target: {}", no_account(&e.to_string())))
}

fn agent_policy(live: &Live, id: &str) -> RunPolicy {
    let row = ai_env_cli::bridge::vm::registry::read_row(&live.paths, id).unwrap().unwrap();
    RunPolicy::from_cfg(&live.cfg.transport, &row, None)
}

fn audit_text(live: &Live) -> String {
    std::fs::read_to_string(live.paths.audit()).unwrap_or_default()
}

#[tokio::test]
#[ignore = "live, starts a MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_agent_exec_roundtrip() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (_, vm, _) = start(&api, &ep, &live, &guard, &test_plan(&live, None)).await;
    ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap();
    let env = AgentEnv { api: &api, ep: &ep, paths: &live.paths, target: agent_target(&live, &vm.id), policy: agent_policy(&live, &vm.id), dial: AgentDial::default() };
    let mut input = b"hello\nsecond line\n".to_vec();
    input.extend_from_slice(&[0x00, 0xff, 0xfe, b'\n']);
    input.extend(std::iter::repeat_n(b'x', 200_000));
    let t = std::time::Instant::now();
    let (out, err, pid, exit) = agent_exec(&env, SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60), id: None, claude: Vec::new() }, input.clone()).await;
    eprintln!("live_agent_exec_roundtrip: {} bytes round trip in {} ms; pid {pid:?}; exit {exit:?}", input.len(), t.elapsed().as_millis());
    assert_eq!(out.len(), input.len(), "stdout length");
    assert!(out == input, "stdout differs from stdin");
    assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
    assert_eq!((exit.code, exit.signal), (Some(0), None));
    assert!(pid.is_some_and(|p| p > 1), "{pid:?}");
    let t = std::time::Instant::now();
    vmrun::terminate_and_record(&api, &live.paths, &vm.id, "test", Some(Poll::SETTLE)).await.unwrap();
    eprintln!("live_agent_exec_roundtrip: TERMINATED after {} ms", t.elapsed().as_millis());
}

/// 20 000 lines over about 5 s (a 0.05 s pause every 200 lines), then exit
/// 0: it outlives the cut after the first chunk plus the D22 ladder (TERM
/// at +0.8 s, KILL at +1.2 s) by a wide margin, so a lost socket that killed
/// it shows (critic H1), as the `reattach` probe's producer does.
const LIVE_PRODUCER: &str = "i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); if [ $((i % 200)) -eq 0 ]; then sleep 0.05; fi; done";

#[tokio::test]
#[ignore = "live, starts a MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_agent_reattach() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (_, vm, _) = start(&api, &ep, &live, &guard, &test_plan(&live, None)).await;
    ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap();
    let env = AgentEnv { api: &api, ep: &ep, paths: &live.paths, target: agent_target(&live, &vm.id), policy: agent_policy(&live, &vm.id), dial: AgentDial::default() };

    // Session 1: a producer with a null stdin, cut after the first chunk.
    let (io1, c1) = spawn_channels(16);
    drop(c1.input);
    let mut ev1 = c1.events;
    let consumed1 = c1.consumed.clone();
    let (mut out, mut last_seq, mut sid, mut pid1, mut chunks) = (Vec::new(), 0u64, None, None, 0u32);
    let mut s1 = Box::pin(run_spawn(&env, Start::New(SpawnSpec { argv: vec!["sh".into(), "-c".into(), LIVE_PRODUCER.into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(300), id: None, claude: Vec::new() }), io1));
    loop {
        tokio::select! {
            ev = ev1.recv() => match ev {
                Some(SpawnEvent::Started { spawn_id, pid, .. }) => { sid = Some(spawn_id); pid1 = Some(pid); }
                Some(SpawnEvent::Stdout { seq, bytes }) => { out.extend_from_slice(&bytes); last_seq = seq; consumed1.stdout_done(seq); chunks += 1; if chunks >= 1 && sid.is_some() { break; } }
                Some(_) => {}
                None => break,
            },
            r = &mut s1 => { r.unwrap_or_else(|e| panic!("session 1: {}", no_account(&e.to_string()))); break; }
        }
    }
    drop(s1);
    let sid = sid.expect("a spawned frame before the cut");

    // Session 2: reattach and collect the rest.
    let (io2, c2) = spawn_channels(16);
    drop(c2.input);
    let mut ev2 = c2.events;
    let consumed2 = c2.consumed.clone();
    let mut pid2 = None;
    let mut s2 = Box::pin(run_spawn(&env, Start::Attach { spawn_id: sid.clone(), from_seq: Some(last_seq + 1), err_from_seq: None }, io2));
    let outcome2 = loop {
        tokio::select! {
            ev = ev2.recv() => match ev {
                Some(SpawnEvent::Started { pid, .. }) => pid2 = Some(pid),
                Some(SpawnEvent::Stdout { seq, bytes }) => { out.extend_from_slice(&bytes); consumed2.stdout_done(seq); }
                Some(_) => {}
                None => {}
            },
            r = &mut s2 => break r,
        }
    };
    while let Ok(ev) = ev2.try_recv() {
        if let SpawnEvent::Stdout { bytes, .. } = ev {
            out.extend_from_slice(&bytes);
        }
    }
    let outcome2 = outcome2.unwrap_or_else(|e| panic!("session 2 (reattach): {}", no_account(&e.to_string())));

    let mut seen = vec![0u32; 20000];
    for line in String::from_utf8_lossy(&out).lines() {
        if let Some(n) = line.strip_prefix("line-").and_then(|s| s.parse::<usize>().ok()) {
            if n < 20000 {
                seen[n] += 1;
            }
        }
    }
    let missing = seen.iter().filter(|c| **c == 0).count();
    let doubled = seen.iter().filter(|c| **c > 1).count();
    eprintln!("live_agent_reattach: cut after {chunks} chunk(s); pid {pid1:?} → {pid2:?}; missing {missing}, doubled {doubled}; exit {:?}", outcome2.exit);
    assert_eq!((missing, doubled), (0, 0), "no line lost or doubled across the reattach");
    assert!(pid1.is_some() && pid1 == pid2, "the same pid across the reattach: {pid1:?} vs {pid2:?}");
    assert_eq!((outcome2.exit.code, outcome2.exit.signal), (Some(0), None), "the producer ran to its end: the cut did not kill it");
}

#[tokio::test]
#[ignore = "live, 65 minutes, one MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 AI_ENV_AWS_SLOW=1 (make test-aws SLOW=1)"]
async fn live_agent_rotation() {
    if !live() {
        return;
    }
    if std::env::var("AI_ENV_AWS_SLOW").as_deref() != Ok("1") {
        eprintln!("skipped: set AI_ENV_AWS_SLOW=1 (make test-aws SLOW=1) for the 65-minute rotation hold");
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    // Max duration and idle both well past the hold: the only socket change is the token rotation.
    let flags = RunFlags { max_duration_s: Some(4500), idle_s: Some(4500), label: Some("test-rotation".into()), purpose: "test", imply_internet: true, ..RunFlags::default() };
    let plan = RunPlan::from_cfg(&live.cfg, &flags).unwrap_or_else(|e| panic!("rotation plan: {e}"));
    let (_, vm, _) = start(&api, &ep, &live, &guard, &plan).await;
    ai_env_cli::bridge::vm::health::read_health(&api, &ep, &live.paths, &vm.id, ai_env_cli::bridge::vm::health::Backoff::HEALTH).await.unwrap();
    // This tests the proactive rotation, whatever `[transport] rotation` the operator chose (runbook step 10 may set `lazy`).
    let mut policy = agent_policy(&live, &vm.id);
    policy.rotation = Rotation::Proactive;
    let env = AgentEnv { api: &api, ep: &ep, paths: &live.paths, target: agent_target(&live, &vm.id), policy, dial: AgentDial::default() };

    // A line a minute for 65 minutes, then EOF: cat echoes each, the session rotates once at T−10 min.
    let (io, c) = spawn_channels(16);
    let feed = c.input.clone();
    let feeder = tokio::spawn(async move {
        for i in 0..65u32 {
            if feed.send(SpawnInput::Stdin(format!("line {i}\n").into_bytes())).await.is_err() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
        let _ = feed.send(SpawnInput::StdinEof).await;
    });
    let mut events = c.events;
    let consumed = c.consumed.clone();
    // Every echoed line, and the session's notes: a failed rotation attempt is only a note.
    let consumer = tokio::spawn(async move {
        let (mut lines, mut notes) = (0u32, Vec::new());
        while let Some(ev) = events.recv().await {
            match ev {
                SpawnEvent::Stdout { seq, bytes } => {
                    lines += bytes.iter().filter(|b| **b == b'\n').count() as u32;
                    consumed.stdout_done(seq);
                }
                SpawnEvent::Note(n) => notes.push(n),
                _ => {}
            }
        }
        (lines, notes)
    });
    let outcome = run_spawn(&env, Start::New(SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(300), id: None, claude: Vec::new() }), io).await;
    drop(c.input);
    drop(c.control);
    feeder.abort();
    let (lines, notes) = consumer.await.unwrap();
    let shown = no_account(&notes.join(" | "));
    let outcome = outcome.unwrap_or_else(|e| panic!("live_agent_rotation: the session ended with an error: {} (notes: {shown})", no_account(&e.to_string())));
    let audit = audit_text(&live);
    let count = |event: &str| audit.lines().filter(|l| l.contains(&format!("\"{event}\""))).count();
    let (rotations, remints, reconnects) = (count("agent_rotate"), count("agent_remint"), count("agent_reconnect"));
    eprintln!("live_agent_rotation: {lines} lines echoed; exit {:?}; agent_rotate×{rotations}, agent_remint×{remints}, agent_reconnect×{reconnects}; notes: {shown}", outcome.exit);
    assert_eq!((outcome.exit.code, outcome.exit.signal), (Some(0), None), "cat exited cleanly after EOF");
    assert_eq!(rotations, 1, "exactly one proactive rotation over 65 minutes (audit: {})", no_account(&audit));
    // A failed rotation attempt (a 403 or a 429 on its own dial, a failed mint, a refused hello) writes no
    // agent_remint and no agent_reconnect: the session notes it and tries again, and the retry's rotation is the
    // one agent_rotate above.
    let failed: Vec<&str> = notes.iter().map(String::as_str).filter(|n| n.starts_with("the token rotation failed")).collect();
    assert!(failed.is_empty(), "the rotation succeeded at its first attempt: {}", no_account(&failed.join(" | ")));
    // The session heals a 403 on its first dial or a reconnect's (one re-mint) and a close (a reconnect) on its own: either would pass unseen without these.
    assert_eq!(remints, 0, "no re-mint: no 403 on the first dial or a reconnect's, and no token down to its last 5 min (the rotation came first) (audit: {})", no_account(&audit));
    assert_eq!(reconnects, 0, "no close: the socket was replaced only by the rotation (audit: {})", no_account(&audit));
    assert_eq!(lines, 65, "every line echoed: none lost across the rotation's hello-resume and stdin resend");
}

// ---- S7: the runtime key reads the egress connector, and the credential gate passes live ----
//
// Part B (Mike's terminal, `make test-aws`). The first starts no VM: the runtime key's own hand-signed
// GetNetworkConnector (D5), by the configured ARN (its colons percent-encoded on the wire) and by the bare id. The
// second starts one vpc VM without --shell and runs the whole credential gate on what the platform reports for it,
// with the real recorded egress checks and dns-path rows (read only). Neither needs the proxy running.

use ai_env_cli::bridge::egress::{credential_gate, newest_dns_path, normalize_connector, ConnectorFacts, EgressVerified, LiveEcho};
use ai_env_cli::bridge::vm::registry::VmRow;

/// The configured egress connector, normalised (no `:N` version suffix).
fn live_connector(live: &Live) -> String {
    let arn = live.cfg.aws.egress_connector_arn.clone().filter(|a| !a.trim().is_empty()).expect("[aws].egress_connector_arn (make infra-status WRITE=1)");
    normalize_connector(&arn)
}

/// GetNetworkConnector with the runtime key, as facts; a refusal names the likely cause.
async fn connector_facts(api: &SdkMicrovmApi, identifier: &str, what: &str) -> ConnectorFacts {
    let doc = api
        .get_network_connector(identifier)
        .await
        .unwrap_or_else(|e| panic!("GetNetworkConnector by {what} with the runtime key: {} (AccessDenied: the IAM grant does not match, make deploy; a signature error: the path encoding)", no_account(&e.to_string())));
    ConnectorFacts::from_get(&doc).unwrap_or_else(|| panic!("GetNetworkConnector by {what}: not an ACTIVE connector with complete facts: {}", no_account(&doc.to_string())))
}

#[tokio::test]
#[ignore = "live, read-only, no VM: AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_runtime_key_reads_the_egress_connector() {
    if !live() {
        return;
    }
    let live = live_world();
    let api = connect(&live.creds).await;
    let arn = live_connector(&live);
    let id = arn.rsplit(':').next().unwrap_or_default().to_string();
    let by_arn = connector_facts(&api, &arn, "ARN").await;
    let by_id = connector_facts(&api, &id, "id").await;
    eprintln!("live_runtime_key_reads_the_egress_connector: Id {}, version {:?}, {}, subnets {:?}, security groups {:?}", by_arn.id, by_arn.version, by_arn.network_protocol, by_arn.subnet_ids, by_arn.security_group_ids);
    assert_eq!(by_arn, by_id, "one connector, whichever identifier names it");
    assert_eq!(by_arn.id, id, "the configured ARN ends in the connector's id");
    // What the gate compares with: the facts the newest passing egress check recorded for this connector.
    let real = Paths::resolve().expect("the real bridge root");
    let verified = EgressVerified::load(&real).unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
    let newest = verified.records.iter().filter(|r| r.connector == arn).max_by(|a, b| a.at.cmp(&b.at)).unwrap_or_else(|| panic!("no passing egress check is recorded for {} (run ai-env egress check)", no_account(&arn)));
    eprintln!("live_runtime_key_reads_the_egress_connector: compared with the check recorded {} for image version {}", newest.at, newest.image_version);
    assert_eq!(by_arn, newest.connector_facts, "the runtime key reads the facts the operator's check recorded");
}

#[tokio::test]
#[ignore = "live, starts a vpc MicroVM (Mike's account): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_credential_gate_passes_for_a_fresh_vpc_vm() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    // A vpc VM without --shell: the gate refuses a --shell VM by design.
    let flags = RunFlags { max_duration_s: Some(900), label: Some("test-gate".into()), egress: Some(vmrun::Egress::Vpc), purpose: "test", ..RunFlags::default() };
    let plan = RunPlan::from_cfg(&live.cfg, &flags).unwrap_or_else(|e| panic!("gate run plan: {e} (make infra-status WRITE=1 records [aws].egress_connector_arn)"));
    let (row, _, running_ms) = start(&api, &ep, &live, &guard, &plan).await;
    // The live reads the gate takes just before a credential would be unsealed.
    let vm = api.get(&row.id).await.unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
    let versions = api.list_image_versions(&vm.image_arn).await.unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
    let created = versions.iter().find(|v| v.version == vm.image_version).and_then(|v| v.created_at_unix);
    let configured = live.cfg.aws.egress_connector_arn.clone().unwrap_or_default();
    let facts = connector_facts(&api, &live_connector(&live), "ARN").await;
    let alias = ConnectorAlias::load(&live.paths, &configured);
    let echo = LiveEcho { connectors: &vm.egress, ingress: &vm.ingress, image: (&vm.image_arn, &vm.image_version), alias: alias.as_ref(), connector: Some(&facts), image_created_at: created };
    eprintln!("live_credential_gate_passes_for_a_fresh_vpc_vm: {} RUNNING after {running_ms} ms; image version {}; ingress {:?}; egress {:?}", row.id, vm.image_version, vm.ingress, no_account(&vm.egress.join(", ")));
    let real = Paths::resolve().expect("the real bridge root");
    let verified = EgressVerified::load(&real).unwrap_or_else(|e| panic!("{}", no_account(&e.to_string())));
    let dns = newest_dns_path(&real);
    let now = ai_env_cli::wire::time::unix_now();
    match credential_gate(&live.cfg, &row, &echo, &verified, &dns, now) {
        Ok(pass) => {
            eprintln!("live_credential_gate_passes_for_a_fresh_vpc_vm: GatePass for {} (image version {})", pass.vm_id(), pass.image_version());
            assert_eq!(pass.vm_id(), row.id);
            pass.check(&row.id, now).unwrap_or_else(|r| panic!("[{}] {}", r.condition, r.why));
        }
        Err(r) => panic!("the credential gate refused {}: [{}] {}", row.id, r.condition, no_account(&r.why)),
    }
    // The same VM recorded as --shell is refused by its row alone, whatever the live reads say.
    let shell = VmRow { shell: true, ..row.clone() };
    assert_eq!(credential_gate(&live.cfg, &shell, &echo, &verified, &dns, now).unwrap_err().condition, "shell_row");
}

// ---- S7: credentials end to end (AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1: make test-aws CRED=1) ----
//
// These run the real `ai-env vm exec` (this Mac's keystore, PATH and Touch
// ID: one for the test process (`LIVE_CREDS`), then one per command with a
// current combined.env, two for `--credential-file` (the runtime key, then
// the file)) against a VM the test started in its temp bridge root, which
// also holds copies of the sealed setup-token, combined.env, the egress
// records and the dns-path rows.
// They make real model requests with the operator's token (T7.4), and refuse
// a garbage token the test seals itself to this Mac's recipients without a
// prompt (T7.5).
//
// Their VMs may hold the operator's real token, and every record of that
// (rows, audit) lives only in the temporary root, unknown to `creds status`
// and `creds forget`: so each test terminates its VMs on every path its
// process lives through. A failed assertion or a command past its limit
// unwinds into the `VmGuard`; a Ctrl-C, SIGTERM or SIGHUP (the terminal
// closed) is caught once ([`Interrupts`]), stops the running command, fails
// the test the same way and then ends the run, and no print on that way
// out can stop it (the terminal may be gone). Each test names the VM that
// may receive the token, with the command that ends it should the process
// die first (a second signal, SIGKILL). Each ends with a sweep for a token
// in the clear.

use ai_env_cli::wire::redact::scrub;
use std::io::Write as _;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// The signal that interrupted a credential test (0: none).
static CRED_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Only records the signal: an atomic store is async-signal-safe.
extern "C" fn record_cred_signal(sig: libc::c_int) {
    CRED_SIGNAL.store(sig, Ordering::SeqCst);
}

/// SIGINT, SIGTERM and SIGHUP caught once while a credential test runs (the
/// next one takes its default course at once; one ignored at the start
/// stays ignored), the previous dispositions restored when it drops. Made
/// first in each test, so it drops last: after the `VmGuard` has terminated
/// the test's VMs, a caught signal ends the run instead of moving on to the
/// next test.
struct Interrupts {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Interrupts {
    fn catch() -> Interrupts {
        CRED_SIGNAL.store(0, Ordering::SeqCst);
        let mut caught = Interrupts { previous: Vec::new() };
        let handler: extern "C" fn(libc::c_int) = record_cred_signal;
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: sigaction(2) on zeroed (valid) structs; the handler only stores to an atomic.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &raw mut old) != 0 || old.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler as libc::sighandler_t;
                act.sa_flags = libc::SA_RESETHAND | libc::SA_RESTART;
                libc::sigemptyset(&raw mut act.sa_mask);
                if libc::sigaction(sig, &raw const act, std::ptr::null_mut()) == 0 {
                    caught.previous.push((sig, old));
                }
            }
        }
        caught
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        for (sig, old) in self.previous.drain(..).rev() {
            // SAFETY: restores a disposition sigaction(2) itself returned.
            unsafe { libc::sigaction(sig, &raw const old, std::ptr::null_mut()) };
        }
        let sig = CRED_SIGNAL.load(Ordering::SeqCst);
        if sig != 0 {
            // Not `eprintln!`: after a SIGHUP every write to the terminal fails, and a panic here would skip the exit.
            let _ = writeln!(std::io::stderr(), "interrupted by signal {sig}: the guard has dealt with the test's VMs (above); ending the run");
            std::process::exit(128 + sig);
        }
    }
}

/// Offline: while [`Interrupts`] lives, a SIGINT, a SIGTERM and a SIGHUP are
/// each recorded instead of ending the process, once (the next would take
/// its default course), and its drop puts the previous dispositions back. A
/// signal this run ignores stays ignored and is skipped.
#[test]
fn interrupts_record_each_signal_once_and_restore_the_dispositions() {
    // SAFETY: sigaction(2) only reads into a zeroed (valid) struct here.
    let disposition = |sig: libc::c_int| unsafe {
        let mut now: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(sig, std::ptr::null(), &raw mut now), 0);
        now.sa_sigaction
    };
    let sigs = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
    let before = sigs.map(disposition);
    let handler: extern "C" fn(libc::c_int) = record_cred_signal;
    let caught = Interrupts::catch();
    // Each raised only when caught (else it would end this run) and taken back at once, so neither the drop nor a failed assertion ends this run; judged after the drop.
    let mut seen = Vec::new();
    for (sig, was) in sigs.into_iter().zip(before) {
        if was == libc::SIG_IGN {
            eprintln!("skipped: signal {sig} is ignored in this run, so it stays ignored");
            continue;
        }
        let installed = disposition(sig) == handler as libc::sighandler_t;
        // SAFETY: raise(3) runs the handler on this thread; it only stores to an atomic.
        let raised = installed && unsafe { libc::raise(sig) } == 0;
        seen.push((sig, raised, CRED_SIGNAL.swap(0, Ordering::SeqCst), disposition(sig)));
    }
    drop(caught);
    for (sig, raised, recorded, after_one) in seen {
        assert!(raised, "signal {sig} is caught (else raising it would end this run)");
        assert_eq!(recorded, sig, "signal {sig} recorded, and the process lives on");
        assert_eq!(after_one, libc::SIG_DFL, "a second signal {sig} takes its default course");
    }
    assert_eq!(sigs.map(disposition), before, "the previous dispositions are back");
}

/// Offline: a caught signal ends the run with 128 + its number even when
/// nothing can be printed any more (the terminal closed: SIGHUP, then every
/// write to it fails), where a panicking print would let the next test
/// start. The test runs itself again as a child, with `--nocapture` and a
/// stderr nobody reads; the child raises SIGHUP under [`Interrupts`] and
/// drops it.
#[test]
fn a_caught_signal_ends_the_run_with_nowhere_to_print() {
    use std::os::unix::process::CommandExt as _;
    const TEST: &str = "a_caught_signal_ends_the_run_with_nowhere_to_print";
    // The child's mark: its parent's pid, which no exported value matches.
    const PARENT: &str = "AI_ENV_TEST_INTERRUPTS_PARENT";
    if std::env::var(PARENT).ok() == Some(std::os::unix::process::parent_id().to_string()) {
        let caught = Interrupts::catch();
        // SAFETY: raise(3) runs the handler on this thread; it only stores to an atomic.
        unsafe { libc::raise(libc::SIGHUP) };
        drop(caught);
        panic!("the run went on after a caught SIGHUP");
    }
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args([TEST, "--exact", "--nocapture", "--test-threads=1"]).env(PARENT, std::process::id().to_string()).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(writer);
    // As from a terminal: a `nohup` above this run would hand SIGHUP down ignored.
    // SAFETY: runs in the forked child before exec; signal(2) is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the child run of {TEST} hung");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(128 + libc::SIGHUP), "{}", String::from_utf8_lossy(&out.stdout));
}

/// How long one `ai-env` command of a credential test may run (a Touch ID,
/// and a model's answer through the VM).
const CRED_COMMAND_LIMIT: Duration = Duration::from_secs(300);

/// Says which VM may now receive the operator's token, and what ends it if
/// this process dies before its `VmGuard` can (its row lives only in the
/// test's temporary root).
fn announce_holder(test: &str, id: &str) {
    eprintln!("{test}: {id} may receive the setup-token; the guard terminates it when the test ends, and if this run is killed first: ai-env vm terminate {id} --yes");
}

/// How many setup-tokens in the clear `hay` holds: `sk-ant-oat01-` then 20
/// or more token characters, the part B leak grep (B15). The test cannot
/// know the sealed token's value without one more Touch ID, so its shape is
/// what is looked for.
fn token_shapes(hay: &[u8]) -> usize {
    const MARK: &[u8] = b"sk-ant-oat01-";
    let tail = |c: &u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-');
    (0..hay.len().saturating_sub(MARK.len() + 19)).filter(|&i| hay[i..].starts_with(MARK) && hay[i + MARK.len()..i + MARK.len() + 20].iter().all(tail)).count()
}

/// Offline: the credential tests' sweep counts what part B's leak grep
/// matches (the kind marker and 20 or more token characters) and nothing
/// less: the setup-token's metadata line and a masked token are no tokens.
#[test]
fn token_shapes_are_what_the_leak_grep_matches() {
    let tok = format!("sk-ant-oat01-{}", "Xy9_".repeat(5));
    assert_eq!(token_shapes(format!("a {tok} b").as_bytes()), 1);
    assert_eq!(token_shapes(tok.as_bytes()), 1, "at the very end");
    assert_eq!(token_shapes(&tok.as_bytes()[..tok.len() - 1]), 0, "19 characters");
    assert_eq!(token_shapes(format!("{tok}\n{tok}").as_bytes()), 2);
    assert_eq!(token_shapes(b"# ai-env-meta: kind=setup-token prefix=sk-ant-oat01- chars=108"), 0);
    assert_eq!(token_shapes(b"sk-ant-[redacted:len=108]"), 0);
}

/// No setup-token in the clear in any output of the test's commands nor in
/// any file under its temporary root (rows, audit, the CLI log, state), and
/// none of `known` (values the test made itself), whole or as a 16-byte
/// piece. Places are named, never values.
fn sweep_live(live: &Live, outs: &[&std::process::Output], known: &[&str]) {
    let check = |hay: &[u8], place: &str| {
        assert_eq!(token_shapes(hay), 0, "setup-tokens in the clear in {place}");
        for value in known {
            let v = value.as_bytes();
            let w = v.len().min(16);
            assert!(!v.windows(w).any(|piece| hay.windows(w).any(|h| h == piece)), "a value the test made (or a 16-byte piece of it) in {place}");
        }
    };
    for (n, out) in outs.iter().enumerate() {
        check(&out.stdout, &format!("the stdout of command {}", n + 1));
        check(&out.stderr, &format!("the stderr of command {}", n + 1));
    }
    let mut dirs = vec![live.paths.root.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.is_dir() {
                dirs.push(path);
            } else if meta.is_file() {
                check(&std::fs::read(&path).unwrap_or_default(), &path.display().to_string());
            }
        }
    }
}

fn cred_live() -> bool {
    if !live() {
        return false;
    }
    if std::env::var("AI_ENV_CREDENTIAL_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_CREDENTIAL_TESTS=1 too (make test-aws CRED=1) to deliver the setup-token");
    false
}

/// [`live_world`] with the credential files and the gate's records copied
/// too, and (A1) the Claude accounts' store, so the live rows name the
/// account the installed token is: the tests run as the active account,
/// which this says. Usage they observe is recorded in the copy, never in
/// the real store.
fn cred_world() -> Live {
    let live = live_world();
    let real = Paths::resolve().expect("the real bridge root");
    for (from, to) in [
        (real.setup_token_env(), live.paths.setup_token_env()),
        (real.combined_env(), live.paths.combined_env()),
        (real.egress_verified(), live.paths.egress_verified()),
        (real.probes(), live.paths.probes()),
        (real.accounts_state(), live.paths.accounts_state()),
    ] {
        if from.exists() {
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(&from, &to).unwrap();
        }
    }
    assert!(live.paths.setup_token_env().exists(), "no sealed setup-token: run `ai-env creds setup-token` first");
    let tag = ai_env_cli::bridge::agent::credential::seal_tag(&live.paths.setup_token_env()).unwrap_or_default();
    if let Some(name) = ai_env_cli::bridge::accounts::label(&live.paths, &tag) {
        eprintln!("live credential tests run as Claude account {name}");
    }
    live
}

/// `ai-env <args>` in the test's bridge root, as the operator runs it (lab
/// knobs removed); its stderr is shown with tokens and account ids masked.
/// Bounded and interruptible: past [`CRED_COMMAND_LIMIT`], or 10 s after a
/// caught signal (one from the terminal reached the command too), it gets
/// SIGTERM (it closes a Touch ID dialog and detaches on its own), then
/// SIGKILL 5 s later, and the test fails, so its `VmGuard` acts.
fn ai_env_live(live: &Live, args: &[&str]) -> std::process::Output {
    ai_env_live_within(live, args, CRED_COMMAND_LIMIT)
}

/// [`ai_env_live`] bounded by `limit` in place of [`CRED_COMMAND_LIMIT`] (S9:
/// a 1 GiB chat's stage, with the restore of `--warm`, and its sync).
fn ai_env_live_within(live: &Live, args: &[&str], limit: Duration) -> std::process::Output {
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
    let what = args.iter().take(3).copied().collect::<Vec<_>>().join(" ");
    assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "interrupted before ai-env {what}");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env"));
    cmd.args(args).env("AI_ENV_BRIDGE_DIR", &live.paths.root).env_remove("AI_ENV_BRIDGE_CONFIG").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AI_ENV_BRIDGE_LAB_") || k.starts_with("CLAUDE_CODE_") {
            cmd.env_remove(&k);
        }
    }
    let started = Instant::now();
    let mut child = cmd.spawn().expect("ai-env runs");
    let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let (mut asked, mut termed) = (None::<Instant>, None::<Instant>);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for ai-env") {
            break status;
        }
        if asked.is_none() && CRED_SIGNAL.load(Ordering::SeqCst) != 0 {
            asked = Some(Instant::now());
        }
        let due = started.elapsed() > limit || asked.is_some_and(|t| t.elapsed() > Duration::from_secs(10));
        match termed {
            None if due => {
                // SAFETY: kill(2) on our own child, which try_wait just saw running (not reaped).
                unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGTERM) };
                termed = Some(Instant::now());
            }
            Some(t) if t.elapsed() > Duration::from_secs(5) => {
                let _ = child.kill();
                break child.wait().expect("reap ai-env");
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = std::process::Output { status, stdout: stdout.join().unwrap_or_default(), stderr: stderr.join().unwrap_or_default() };
    eprintln!("ai-env {what}: exit {:?} in {} ms\n{}", out.status.code(), started.elapsed().as_millis(), no_account(&scrub(&String::from_utf8_lossy(&out.stderr))));
    let sig = CRED_SIGNAL.load(Ordering::SeqCst);
    assert_eq!(sig, 0, "interrupted during ai-env {what}: the guard terminates the test's VMs");
    assert!(termed.is_none(), "ai-env {what} ran past {limit:?} and was stopped");
    out
}

fn vpc_plan(live: &Live) -> RunPlan {
    let flags = RunFlags { max_duration_s: Some(900), label: Some("test-cred".into()), egress: Some(vmrun::Egress::Vpc), purpose: "test", ..RunFlags::default() };
    RunPlan::from_cfg(&live.cfg, &flags).unwrap_or_else(|e| panic!("vpc run plan: {e}"))
}

/// The JSON result `claude -p --output-format json` printed: (is_error, result).
fn claude_json(stdout: &[u8]) -> (Option<bool>, String) {
    let v: serde_json::Value = String::from_utf8_lossy(stdout).lines().rev().find_map(|l| serde_json::from_str(l).ok()).unwrap_or_default();
    (v["is_error"].as_bool(), v["result"].as_str().unwrap_or_default().to_string())
}

/// T7.4: a credentialed `claude -p` answers OK through the endpoint and the
/// proxy, twice on one VM, with one delivery: the second finds the VM's copy.
/// No token in the clear in either command's output or the temporary root.
#[tokio::test]
#[ignore = "live, starts a MicroVM and asks the model: AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
async fn live_credential_claude_answers_ok_twice_with_one_delivery() {
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = cred_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (row, _, running_ms) = start(&api, &ep, &live, &guard, &vpc_plan(&live)).await;
    eprintln!("live_credential_claude_answers_ok_twice_with_one_delivery: {} RUNNING after {running_ms} ms", row.id);
    announce_holder("live_credential_claude_answers_ok_twice_with_one_delivery", &row.id);
    let ask = ["vm", "exec", row.id.as_str(), "--with-credential", "--", "claude", "-p", "Reply with exactly OK", "--output-format", "json"];
    let mut outs = Vec::new();
    for round in 1..=2 {
        let out = ai_env_live(&live, &ask);
        assert_eq!(out.status.code(), Some(0), "round {round}");
        let (is_error, result) = claude_json(&out.stdout);
        assert_eq!(is_error, Some(false), "round {round}");
        assert!(result.trim().trim_end_matches('.').eq_ignore_ascii_case("ok"), "round {round}: the answer is {} characters", result.len());
        outs.push(out);
    }
    let rows = ai_env_cli::bridge::audit::read_rows(&live.paths.audit(), None).unwrap();
    let delivered = rows.iter().filter(|r| r["event"] == "credential_deliver" && r["detail"]["id"] == row.id).count();
    assert_eq!(delivered, 1, "one delivery for two commands");
    sweep_live(&live, &outs.iter().collect::<Vec<_>>(), &[]);
}

/// T7.5, the GO/NO-GO rehearsal: a garbage token (sealed here to this Mac's
/// recipients, no prompt) given with `--credential-file` is refused by
/// Anthropic: exit 5 (stopped at the third retry 401, or ended by itself
/// with its 401 text), no claude left on the VM. Neither the garbage token
/// nor any other is in the clear in the output or the temporary root. What
/// B7 keeps for part B is printed first, before any assertion, so a run whose
/// words the watch missed still shows them (B14 repeats B7 here): claude's
/// `api_retry` lines and its last `result` line, scrubbed and cut to 400
/// characters each, and how the `credential_rejected` rows say it was seen.
#[tokio::test]
#[ignore = "live, starts a MicroVM: AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
async fn live_credential_garbage_token_is_refused_with_exit_5() {
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = cred_world();
    let key = live.cfg.creds.key.clone();
    let store = ai_env_cli::store::Keystore::resolve(None).expect("keystore");
    let garbage = format!("sk-ant-oat01-{}", "Gq7_".repeat(24));
    let sealed = ai_env_cli::age_cmd::AgeTool::probe().unwrap().encrypt(&store.recipients_path(&key), format!("CLAUDE_CODE_OAUTH_TOKEN={garbage}\n").as_bytes()).unwrap();
    let file = live.paths.root.join("garbage.env");
    std::fs::write(&file, ai_env_cli::container::write(&sealed)).unwrap();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (row, _, _) = start(&api, &ep, &live, &guard, &vpc_plan(&live)).await;
    announce_holder("live_credential_garbage_token_is_refused_with_exit_5", &row.id);
    let path = file.display().to_string();
    let out = ai_env_live(&live, &["vm", "exec", row.id.as_str(), "--credential-file", &path, "--", "claude", "-p", "Reply OK", "--output-format", "stream-json", "--verbose"]);
    // B7's kept output, first: claude's own words to a refused token, even from a run an assertion below fails.
    let rows = ai_env_cli::bridge::audit::read_rows(&live.paths.audit(), None).unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    let cut = |line: &str| scrub(line).chars().take(400).collect::<String>();
    for line in said.lines().filter(|l| l.contains("\"api_retry\"")) {
        eprintln!("live_credential_garbage_token_is_refused_with_exit_5: api_retry line: {}", cut(line));
    }
    if let Some(last) = said.lines().rev().find(|l| serde_json::from_str::<serde_json::Value>(l).is_ok_and(|v| v["type"] == "result")) {
        eprintln!("live_credential_garbage_token_is_refused_with_exit_5: last result line: {}", cut(last));
    }
    let how: Vec<&str> = rows.iter().filter(|r| r["event"] == "credential_rejected").filter_map(|r| r["detail"]["how"].as_str()).collect();
    eprintln!("live_credential_garbage_token_is_refused_with_exit_5: exit {:?}, credential_rejected how={}", out.status.code(), how.join(","));
    assert_eq!(out.status.code(), Some(5), "a refused token is exit 5");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Anthropic refused the delivered setup-token"), "the ai-env line names the refusal");
    // No claude left: /health/detail with the row's session token (no Touch ID).
    let bearer = Secret::new(row.session_token.clone().unwrap_or_default());
    let token = ai_env_cli::bridge::vm::token::mint_internal(&api, &live.paths, &row.id).await.unwrap();
    let t = std::time::Instant::now();
    loop {
        let detail = ep.get_health_detail(&row.endpoint.clone().unwrap_or_default(), &token, &bearer).await.unwrap().detail.unwrap();
        if detail.spawns.iter().all(|s| !s.status.alive) {
            eprintln!("live_credential_garbage_token_is_refused_with_exit_5: no live spawn after {} ms", t.elapsed().as_millis());
            break;
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "a claude still runs 5 s after the refusal");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(rows.iter().any(|r| r["event"] == "credential_rejected"), "audited");
    sweep_live(&live, &[&out], &[&garbage[13..]]);
}

/// T7.5: a credential never enters a VM with internet egress: exit 9 from
/// the local half of the gate, before any Touch ID. Shown by what an unseal
/// leaves, not by the time taken (the operator may answer a prompt quickly):
/// no `credential_unseal` audit row, no countdown and no runtime-key line.
#[tokio::test]
#[ignore = "live, starts a MicroVM: AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
async fn live_credential_never_enters_an_internet_vm() {
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = cred_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let flags = RunFlags { max_duration_s: Some(900), label: Some("test-cred".into()), egress: Some(vmrun::Egress::Internet), purpose: "test", ..RunFlags::default() };
    let plan = RunPlan::from_cfg(&live.cfg, &flags).unwrap();
    let (row, _, _) = start(&api, &ep, &live, &guard, &plan).await;
    let t = Instant::now();
    let out = ai_env_live(&live, &["vm", "exec", row.id.as_str(), "--with-credential", "--", "true"]);
    assert_eq!(out.status.code(), Some(9));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not vpc"));
    let rows = ai_env_cli::bridge::audit::read_rows(&live.paths.audit(), None).unwrap();
    assert!(!rows.iter().any(|r| r["event"] == "credential_unseal"), "no unseal was audited");
    assert!(!err.contains("waiting for Touch ID") && !err.contains("ai-env: runtime key") && !err.contains("ai-env: profile "), "refused before any Touch ID: no countdown and no runtime-key line");
    assert!(t.elapsed() < Duration::from_secs(10), "refused at once");
    sweep_live(&live, &[&out], &[]);
}

// ---- S8: the remote wrapper, live (AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1: make test-aws CRED=1) ----
//
// The real `ai-env-claude` in remote mode as Cursor runs it, the test playing
// the extension (stream-json on the wrapper's stdio, the extension's chat argv
// and entrypoint), in a fixture repository under this checkout's `target/s8/`
// (made anew by each test), which a configured root must hold: else the test
// fails, listing the roots. Each test runs in its own temporary bridge root
// (the credential world's copies) with `[vm] max_duration_s = 900`, so every VM
// its sessions (or commands) start lives at most 15 minutes (S9's 1 GiB round
// trip sets about 120) and has its row there, and `migrate_before_wall_s =
// 300`, so a later chat reuses (or resumes) it for its first ten minutes (at
// the default 1200 s a 900 s VM is never reused):
// `SessionVms` terminates them all on every path the test unwinds through and,
// unless the test already failed, asserts each is gone. The sessions make real
// model requests with the operator's token. Touch IDs: one for the test
// process's runtime key (`LIVE_CREDS`, when a test reads the service itself),
// then one per wrapper process (D1) and one per `ai-env vm` or `box` command,
// with a current combined.env. Each fixture's chat keeps its transcript in S3
// (S9) and its view where Cursor's file would be
// (`~/.claude/projects/<the fixture's slug>/`); each test purges its chats'
// S3 objects at its end, all of them in one `session forget <ids...> --purge`
// (one Touch ID more, none for a test with no chat registered:
// `PurgeTranscripts`, S10 F1).
// `live_wrapper_smoke` is `make s8-smoke`'s body; the API-host test needs
// AI_ENV_AWS_SLOW=1 as well (about four minutes).

use ai_env_cli::bridge::probes::{INIT_COLD_BUDGET_MS, INIT_WARM_BUDGET_MS};
use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
use ai_env_cli::bridge::vm::registry::{self as vm_rows, RowStatus};

/// The extension's chat argv (2.1.282, `tests/common/mod.rs`'s `SESSION_ARGV`).
const CURSOR_CHAT: [&str; 16] = [
    "--output-format",
    "stream-json",
    "--verbose",
    "--input-format",
    "stream-json",
    "--permission-prompt-tool",
    "stdio",
    "--setting-sources=user,project,local",
    "--permission-mode",
    "default",
    "--include-partial-messages",
    "--debug",
    "--debug-to-stderr",
    "--enable-auth-status",
    "--no-chrome",
    "--replay-user-messages",
];

/// How long the extension waits for `initialize`: Cursor's window (the Touch ID, a cold VM and the seed inside it).
const LIVE_INIT_LIMIT: Duration = Duration::from_secs(60);
/// How long one turn of a live chat may take (a model's answer, a tool call through the VM).
const LIVE_TURN_LIMIT: Duration = Duration::from_secs(240);
/// How long a wrapper may take to exit once its stdin closed before the test kills it (the budget is judged apart).
const LIVE_EXIT_LIMIT: Duration = Duration::from_secs(10);

/// [`cred_world`] for a wrapper test: `[vm] max_duration_s = 900` and
/// `migrate_before_wall_s = 300` (`reuse_candidate` takes a VM only with
/// more wall left than that: at the default 1200 none of these would ever be
/// reused), and `vm`'s `[vm]` keys (set last: they win over those two),
/// written into the temporary root's bridge.toml.
fn wrapper_world(vm: &[(&str, toml::Value)]) -> Live {
    let mut live = cred_world();
    let mut doc: toml::Table = toml::from_str(&std::fs::read_to_string(&live.paths.config).unwrap()).expect("the copied bridge.toml");
    let table = doc.entry("vm").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let table = table.as_table_mut().expect("[vm] is a table");
    table.insert("max_duration_s".into(), toml::Value::Integer(900));
    table.insert("migrate_before_wall_s".into(), toml::Value::Integer(300));
    for (k, v) in vm {
        table.insert((*k).to_string(), v.clone());
    }
    std::fs::write(&live.paths.config, toml::to_string(&doc).unwrap()).unwrap();
    live.cfg = BridgeConfig::load(&live.paths).unwrap().expect("bridge.toml");
    live
}

/// `git args` in `dir` with neither the system's nor a global config, the author, committer and dates fixed.
fn fixture_git(dir: &std::path::Path, args: &[&str]) -> String {
    let o = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "ai-env live fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@ai-env.invalid")
        .env("GIT_AUTHOR_DATE", "2026-10-12T08:00:00+00:00")
        .env("GIT_COMMITTER_NAME", "ai-env live fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@ai-env.invalid")
        .env("GIT_COMMITTER_DATE", "2026-10-12T08:00:00+00:00")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("git runs");
    assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// The fixture repository `target/s8/<name>` of this checkout, made anew (one
/// commit on `main`); a configured root must hold it, else the test fails
/// listing the roots.
fn s8_fixture(live: &Live, name: &str) -> std::path::PathBuf {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/s8");
    std::fs::create_dir_all(&base).unwrap();
    let dir = std::fs::canonicalize(&base).unwrap().join(name);
    let roots: Vec<std::path::PathBuf> = live.cfg.roots().iter().map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.to_path_buf())).collect();
    assert!(
        roots.iter().any(|r| dir.starts_with(r)),
        "{} is under no configured root: add target/s8 (or this checkout) to [workspaces].roots in bridge.toml; the roots: {:?}",
        dir.display(),
        live.cfg.roots()
    );
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    fixture_git(&dir, &["init", "-q", "-b", "main"]);
    std::fs::write(dir.join("README.md"), format!("{name}: a fixture of the S8 live tests\n")).unwrap();
    fixture_git(&dir, &["add", "README.md"]);
    fixture_git(&dir, &["commit", "-q", "-m", "fixture"]);
    dir
}

/// A fixture directory removed on drop, on every path the test unwinds
/// through: what a test planted there never outlives it.
struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "guard: could not remove {}: {e} — remove it by hand (a test planted a value there)", self.0.display());
            }
        }
    }
}

/// The VMs a wrapper test's sessions and commands made (`session stage --warm` warms one), all with their rows in its
/// temporary root: on drop every row's VM is terminated (on its own runtime and thread) and, unless the test already
/// failed, each is asserted gone; when it failed, what is left is said.
struct SessionVms {
    creds: RuntimeCreds,
    paths: Paths,
}

impl SessionVms {
    fn new(live: &Live) -> SessionVms {
        SessionVms { creds: live.creds.clone(), paths: live.paths.clone() }
    }
}

impl Drop for SessionVms {
    fn drop(&mut self) {
        let (creds, paths) = (self.creds.clone(), self.paths.clone());
        let (said, left) = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let api = connect(&creds).await;
                let (mut said, mut left) = (Vec::new(), Vec::new());
                for row in vm_rows::list_rows(&paths).unwrap_or_default() {
                    if row.is_pending_row() {
                        left.push(format!("a pending row {} (a run whose VM may exist: ai-env vm gc)", row.stem()));
                        continue;
                    }
                    if row.status != RowStatus::Terminated {
                        said.push(match vmrun::terminate_and_record(&api, &paths, &row.id, "test", Some(Poll::SETTLE)).await {
                            Ok(_) => format!("guard: terminated {}", row.id),
                            Err(e) => format!("guard: could not terminate {}: {} — run: ai-env vm terminate {} --yes (the test's row lived in a temp root)", row.id, no_account(&e.to_string()), row.id),
                        });
                    }
                    match api.get(&row.id).await {
                        Ok(vm) if vm.state.is_terminal() => {}
                        Err(BridgeError::VmNotFound(_)) => {}
                        Ok(vm) => left.push(format!("{} is {}", row.id, vm.state.as_str())),
                        Err(e) => left.push(format!("{}: {}", row.id, no_account(&e.to_string()))),
                    }
                }
                (said, left)
            })
        })
        .join()
        .unwrap_or_else(|_| (Vec::new(), vec!["the guard's thread panicked".to_string()]));
        for line in said {
            let _ = writeln!(std::io::stderr(), "{line}");
        }
        if !left.is_empty() {
            let left = format!("the test's VMs are not all gone: {}", left.join("; "));
            // A test that failed already is told, never panicked again.
            if std::thread::panicking() {
                let _ = writeln!(std::io::stderr(), "guard: {left}");
            } else {
                panic!("{left}");
            }
        }
    }
}

/// One turn of a live chat: its `result` line, the tools claude asked
/// permission for (each allowed), the tools it used, what those returned, and
/// how long the turn took. S10: its user line's uuid, how many of that line's
/// echoes, `system/init` lines and results the host was given, ai-env's
/// informational lines (a move's notes, L3) and the requests claude withdrew
/// (`control_cancel_request`, L4).
#[derive(Default)]
struct LiveTurn {
    result: serde_json::Value,
    asked: Vec<String>,
    used: Vec<String>,
    tool_output: String,
    ms: u128,
    uuid: String,
    echoes: u32,
    inits: u32,
    results: u32,
    notes: Vec<String>,
    cancels: Vec<String>,
}

/// How [`Chat::read_until`] answers claude's `can_use_tool` requests (S10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asks {
    /// Each allowed as asked, at once, as the permission prompt's button would.
    AllowAll,
    /// Each left unanswered and handed back: the test answers it ([`Chat::answer_permission`]).
    Hold,
}

/// One Cursor chat the test plays on the real `ai-env-claude` in remote mode:
/// the extension's argv and entrypoint, its stream-json on the wrapper's stdio
/// (each stdout line read on a thread, its stderr kept as it comes on
/// another), the test's temporary bridge root.
struct Chat {
    test: &'static str,
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    /// The wrapper's stderr so far ([`Chat::stderr_now`]).
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    /// Its reader, joined once the wrapper exited.
    stderr_reader: Option<std::thread::JoinHandle<()>>,
    /// Every stdout line so far, for the sweep.
    stdout: Vec<u8>,
    /// The session id of the newest `system/init`.
    session: Option<String>,
    /// S10: what the chat said since the newest [`Chat::send_user`] ([`Chat::turn_to_result`] hands it over).
    turn: LiveTurn,
    /// When that user line was sent.
    turn_from: Instant,
    /// The wrapper's log in the test's root, when the chat was opened there ([`Chat::log_tail`]).
    log: Option<std::path::PathBuf>,
}

impl Chat {
    /// `ai-env-claude <no claude here> CURSOR_CHAT… extra` in `cwd`: remote mode, the temporary root, the extension's
    /// entrypoint; the lab knobs and every other `CLAUDE_CODE_` name of this shell removed. argv[1] names no file: in
    /// remote mode no Mac binary runs, and a local run of it fails at once.
    fn open(test: &'static str, live: &Live, cwd: &std::path::Path, extra: &[&str]) -> Chat {
        Chat::open_as(test, live, cwd, &live.paths.root.join("no-claude-on-this-mac").join("claude"), extra)
    }

    /// S11: [`Chat::open`] as a chat of the Cursor bundle `version` (`bundle_argv1`: argv[1] names that bundle's
    /// binary under the temporary root, where no file is), so P0 has a V as Cursor's chats do (the census's `ext`,
    /// `claude::plan_for`).
    fn open_bundled(test: &'static str, live: &Live, cwd: &std::path::Path, version: &str, extra: &[&str]) -> Chat {
        Chat::open_as(test, live, cwd, &bundle_argv1(&live.paths.root, version), extra)
    }

    /// [`Chat::open`] with `argv1` as argv[1].
    fn open_as(test: &'static str, live: &Live, cwd: &std::path::Path, argv1: &std::path::Path, extra: &[&str]) -> Chat {
        assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{test}: interrupted before a chat opened");
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env-claude"));
        cmd.arg(argv1).args(CURSOR_CHAT).args(extra).current_dir(cwd);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AI_ENV_BRIDGE_") || k.starts_with("CLAUDE_CODE_") {
                cmd.env_remove(&k);
            }
        }
        cmd.env("AI_ENV_BRIDGE_DIR", &live.paths.root)
            .env("AI_ENV_BRIDGE_MODE", "remote")
            .env("CLAUDE_CODE_ENTRYPOINT", "claude-vscode")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn().expect("ai-env-claude runs");
        announce_touch_id(test, &format!("ai-env-claude (pid {}) in {}", child.id(), cwd.display()));
        let mut chat = Chat::over(test, child);
        chat.log = Some(live.paths.wrapper_log());
        chat
    }

    /// A chat over `child`, its stdio piped: each stdout line read on a thread, its stderr kept as it comes by another.
    fn over(test: &'static str, mut child: std::process::Child) -> Chat {
        use std::io::BufRead as _;
        let (tx, lines) = std::sync::mpsc::channel();
        let out = child.stdout.take().expect("piped stdout");
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(out).lines().map_while(std::result::Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let mut err = child.stderr.take().expect("piped stderr");
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&stderr);
        let stderr_reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut err, &mut buf) {
                    Ok(0) => return,
                    Ok(n) => sink.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return,
                }
            }
        });
        Chat { test, stdin: child.stdin.take(), child, lines, stderr, stderr_reader: Some(stderr_reader), stdout: Vec::new(), session: None, turn: LiveTurn::default(), turn_from: Instant::now(), log: None }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn send(&mut self, line: &serde_json::Value) {
        use std::io::Write as _;
        let test = self.test;
        let stdin = self.stdin.as_mut().unwrap_or_else(|| panic!("{test}: a send after the close"));
        stdin.write_all(format!("{line}\n").as_bytes()).and_then(|()| stdin.flush()).unwrap_or_else(|e| panic!("{test}: the wrapper's stdin: {e}"));
    }

    /// The next stdout line that is JSON, before `until`; `None` at the wrapper's EOF or past `until`.
    fn next(&mut self, until: Instant) -> Option<serde_json::Value> {
        loop {
            assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{}: interrupted: the guard ends the test's VMs", self.test);
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self.lines.recv_timeout(left.min(Duration::from_millis(200))) {
                Ok(line) => {
                    self.stdout.extend_from_slice(line.as_bytes());
                    self.stdout.push(b'\n');
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                    if v["type"] == "system" && v["subtype"] == "init" {
                        self.session = v["session_id"].as_str().map(str::to_string);
                    }
                    return Some(v);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// `initialize`, answered within Cursor's window: how long it took.
    fn initialize(&mut self) -> Duration {
        self.initialize_within(LIVE_INIT_LIMIT)
    }

    /// [`Chat::initialize`] answered within `limit` (S9: the reopen of a 1 GiB
    /// chat, which claude may parse whole before it answers).
    fn initialize_within(&mut self, limit: Duration) -> Duration {
        let t = Instant::now();
        self.send(&serde_json::json!({"type": "control_request", "request_id": "live-init", "request": {"subtype": "initialize"}}));
        loop {
            let Some(v) = self.next(t + limit) else {
                let test = self.test;
                panic!("{test}: no answer to initialize within {limit:?}; the wrapper's stderr: {}", self.stderr_now());
            };
            if v["type"] == "control_response" && v["response"]["request_id"] == "live-init" {
                assert_eq!(v["response"]["subtype"], "success", "{}: initialize answered {v}", self.test);
                return t.elapsed();
            }
        }
    }

    /// One user message and its turn, to its `result`: every `can_use_tool` request is allowed as asked, any other
    /// request of claude's answered with an error.
    fn turn(&mut self, text: &str) -> LiveTurn {
        self.turn_within(text, LIVE_TURN_LIMIT)
    }

    /// [`Chat::turn`] answered within `limit` (S9: the first turn of a
    /// reopened 1 GiB chat, which claude may parse whole first).
    fn turn_within(&mut self, text: &str, limit: Duration) -> LiveTurn {
        let uuid = self.send_user(text);
        self.turn_to_result(&uuid, limit)
    }

    /// S10: one user message (a fresh uuid v7): its uuid. What the chat says from now on is this turn's, until the
    /// next one is sent.
    fn send_user(&mut self, text: &str) -> String {
        let uuid = uuid::Uuid::now_v7().to_string();
        self.turn = LiveTurn { uuid: uuid.clone(), ..LiveTurn::default() };
        self.turn_from = Instant::now();
        self.send(&serde_json::json!({"type": "user", "message": {"role": "user", "content": text}, "parent_tool_use_id": null, "session_id": "", "uuid": uuid}));
        uuid
    }

    /// S10: the chat's lines, each recorded into the turn ([`LiveTurn`]), until `stop` takes one, which is handed
    /// back; under [`Asks::Hold`] a `can_use_tool` request is handed back too, unanswered, whatever `stop` says.
    /// Under [`Asks::AllowAll`] each is allowed as asked; any other request of claude's is answered with an error.
    /// `None` past `limit` from now, or at the wrapper's EOF.
    fn read_until(&mut self, limit: Duration, asks: Asks, mut stop: impl FnMut(&serde_json::Value) -> bool) -> Option<serde_json::Value> {
        let until = Instant::now() + limit;
        loop {
            let v = self.next(until)?;
            if self.record(&v, asks) || stop(&v) {
                return Some(v);
            }
        }
    }

    /// One line into the turn, a request of claude's answered as `asks` says: whether it is a `can_use_tool` held.
    fn record(&mut self, v: &serde_json::Value, asks: Asks) -> bool {
        match v["type"].as_str() {
            Some("control_request") if v["request"]["subtype"] == "can_use_tool" => {
                self.turn.asked.push(v["request"]["tool_name"].as_str().unwrap_or("?").to_string());
                if asks == Asks::Hold {
                    return true;
                }
                self.answer_permission(v, true);
            }
            Some("control_request") => {
                self.send(&serde_json::json!({"type": "control_response", "response": {"subtype": "error", "request_id": v["request_id"], "error": "the live test answers no such request"}}));
            }
            Some("control_cancel_request") => self.turn.cancels.push(v["request_id"].as_str().unwrap_or("?").to_string()),
            Some("assistant") => {
                let blocks = v["message"]["content"].as_array().map(Vec::as_slice).unwrap_or_default();
                self.turn.used.extend(blocks.iter().filter(|b| b["type"] == "tool_use").filter_map(|b| b["name"].as_str().map(str::to_string)));
            }
            Some("user") => {
                if v["isReplay"] == true && !self.turn.uuid.is_empty() && v["uuid"] == self.turn.uuid.as_str() {
                    self.turn.echoes += 1;
                }
                for block in v["message"]["content"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter(|b| b["type"] == "tool_result") {
                    match &block["content"] {
                        serde_json::Value::String(s) => self.turn.tool_output.push_str(s),
                        serde_json::Value::Array(parts) => parts.iter().filter_map(|p| p["text"].as_str()).for_each(|s| self.turn.tool_output.push_str(s)),
                        _ => {}
                    }
                    self.turn.tool_output.push('\n');
                }
            }
            Some("system") if v["subtype"] == "init" => self.turn.inits += 1,
            // ai-env's own (every note of L3's starts so); claude writes the subtype too.
            Some("system") if v["subtype"] == "informational" => {
                if let Some(note) = v["content"].as_str().filter(|c| c.starts_with("ai-env: ")) {
                    self.turn.notes.push(note.to_string());
                }
            }
            Some("result") => {
                self.turn.results += 1;
                self.turn.ms = self.turn_from.elapsed().as_millis();
                self.turn.result = v.clone();
            }
            _ => {}
        }
        false
    }

    /// S10: under [`Asks::Hold`], the turn's next `can_use_tool` request, left unanswered; the test fails past
    /// `limit` from now, or when the turn ends asking none.
    fn held_permission(&mut self, limit: Duration) -> serde_json::Value {
        let test = self.test;
        match self.read_until(limit, Asks::Hold, |v| v["type"] == "result") {
            Some(v) if v["type"] == "control_request" => v,
            Some(v) => panic!("{test}: the turn ended asking no permission: {v}"),
            None => {
                let err = self.stderr_now();
                panic!("{test}: no permission request within {limit:?}; the wrapper's stderr: {err}")
            }
        }
    }

    /// S10: the answer to claude's `can_use_tool` request `req`: allowed as asked, or denied.
    fn answer_permission(&mut self, req: &serde_json::Value, allow: bool) {
        let decision = if allow { serde_json::json!({"behavior": "allow", "updatedInput": req["request"]["input"]}) } else { serde_json::json!({"behavior": "deny", "message": "the live test denies it"}) };
        self.send(&serde_json::json!({"type": "control_response", "response": {"subtype": "success", "request_id": req["request_id"], "response": decision}}));
    }

    /// S10: the turn of the user line `uuid` (the newest [`Chat::send_user`]'s) to its `result`, within `limit` of
    /// now, each `can_use_tool` allowed as asked: the turn, its time from the send.
    fn turn_to_result(&mut self, uuid: &str, limit: Duration) -> LiveTurn {
        let test = self.test;
        assert_eq!(self.turn.uuid, uuid, "{test}: the turn read is the newest user line's");
        if self.turn.results == 0 && self.read_until(limit, Asks::AllowAll, |v| v["type"] == "result").is_none() {
            let (used, asked, notes) = (self.turn.used.clone(), self.turn.asked.clone(), self.turn.notes.clone());
            let err = self.stderr_now();
            let log = self.log_tail();
            panic!("{test}: no result within {limit:?} (tools used: {used:?}, asked for: {asked:?}, notes: {notes:?}); the wrapper's stderr: {err}\nthe wrapper's log, its end:\n{log}");
        }
        std::mem::take(&mut self.turn)
    }

    /// S10: [`wait_for`] with the chat open: its lines read between the probes (each recorded, a request answered
    /// as `asks` says), the wrapper alive throughout; the probe's answer.
    fn wait_for<T>(&mut self, what: &str, limit: Duration, asks: Asks, mut probe: impl FnMut() -> Option<T>) -> T {
        let (test, t) = (self.test, Instant::now());
        loop {
            if let Some(found) = probe() {
                eprintln!("{test}: {what}: after {} ms", t.elapsed().as_millis());
                return found;
            }
            if t.elapsed() >= limit {
                let err = self.stderr_now();
                panic!("{test}: {what}: not within {limit:?}; the wrapper's stderr: {err}");
            }
            self.pause(LIVE_SYNC_POLL, asks, what);
        }
    }

    /// S10: the chat's lines for `dur` (each recorded, every `can_use_tool` allowed), the wrapper alive throughout.
    fn idle(&mut self, dur: Duration) {
        self.pause(dur, Asks::AllowAll, "a pause between turns");
    }

    /// The chat's lines for `dur`, a request answered as `asks` says; the test fails at once when the wrapper exits
    /// meanwhile (`what` is what it waited for).
    fn pause(&mut self, dur: Duration, asks: Asks, what: &str) {
        let until = Instant::now() + dur;
        loop {
            let _ = self.read_until(until.saturating_duration_since(Instant::now()), asks, |_| false);
            if let Ok(Some(status)) = self.child.try_wait() {
                let test = self.test;
                let err = self.stderr_now();
                panic!("{test}: the wrapper exited ({status}) while the test waited for {what}; its stderr: {err}");
            }
            if Instant::now() >= until {
                return;
            }
            // At the wrapper's EOF `read_until` returns at once.
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// S10: the VM the chat's session row names now (`microvm_id`: the newest generation's).
    fn session_vm(&self, live: &Live) -> String {
        let test = self.test;
        let session = self.session.as_deref().unwrap_or_else(|| panic!("{test}: no session id yet"));
        ai_env_cli::bridge::registry::read(&live.paths, session).unwrap().and_then(|r| r.microvm_id).unwrap_or_else(|| panic!("{test}: the session row of {session} names no VM"))
    }

    /// S10: `ai-env vm terminate <vm> --yes` with the chat open, mid-turn or idle: the chat's lines wait on their
    /// thread meanwhile. Its Touch ID is announced first, then `then`'s when given: one the terminate sets off at
    /// once (a move mid-turn asks M1's as soon as the wrapper sees the loss, while the command still waits up to
    /// 30 s for TERMINATED). Exit 0 asserted; its output, for the sweep.
    fn terminate_mid_turn(&self, live: &Live, vm: &str, then: Option<&str>) -> std::process::Output {
        announce_touch_id(self.test, &format!("vm terminate {vm}"));
        if let Some(then) = then {
            announce_touch_id(self.test, then);
        }
        let out = ai_env_live(live, &["vm", "terminate", vm, "--yes"]);
        assert_eq!(out.status.code(), Some(0), "{}: vm terminate {vm}", self.test);
        out
    }

    /// S10, a closed lid's stand-in: the wrapper stopped (SIGSTOP) for `dur`, then continued (SIGCONT). Its
    /// socket goes silent while the VM and its turn go on. A caught signal cuts the stop short and fails the test
    /// (the drop continues the wrapper before it ends it).
    fn stop_for(&mut self, dur: Duration) {
        self.signal(libc::SIGSTOP);
        let t = Instant::now();
        while t.elapsed() < dur && CRED_SIGNAL.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(dur.saturating_sub(t.elapsed()).min(Duration::from_millis(100)));
        }
        self.signal(libc::SIGCONT);
        assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{}: interrupted while the wrapper was stopped", self.test);
    }

    /// `sig` to the wrapper, while it is not reaped.
    fn signal(&mut self, sig: libc::c_int) {
        if let (Ok(None), Ok(pid)) = (self.child.try_wait(), i32::try_from(self.child.id())) {
            // SAFETY: kill(2) on our own child, which try_wait just saw unreaped.
            unsafe { libc::kill(pid, sig) };
        }
    }

    /// The wrapper's stderr so far, all of it once the wrapper exited (S10 reads it live), setup-tokens and
    /// account ids masked.
    /// The last 40 lines of the wrapper's log (its root's `logs/wrapper.log`), scrubbed: what a failed live turn
    /// prints, since the root goes with the test.
    fn log_tail(&self) -> String {
        let text = self.log.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        ai_env_cli::wire::redact::scrub(&lines[lines.len().saturating_sub(40)..].join("\n")).into_owned()
    }

    fn stderr_now(&mut self) -> String {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            if let Some(h) = self.stderr_reader.take() {
                let _ = h.join();
            }
        }
        let bytes = self.stderr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        no_account(&scrub(&String::from_utf8_lossy(&bytes)))
    }

    /// Close the wrapper's stdin (the extension's `stdin.end()`), then its exit: the code, and how long after the close
    /// it came; killed and failed past [`LIVE_EXIT_LIMIT`].
    fn close(&mut self) -> (Option<i32>, Duration) {
        self.stdin = None;
        let t = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for ai-env-claude") {
                return (status.code(), t.elapsed());
            }
            if t.elapsed() > LIVE_EXIT_LIMIT {
                let _ = self.child.kill();
                panic!("{}: the wrapper did not exit within {LIVE_EXIT_LIMIT:?} of its stdin's close", self.test);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Wait (bounded by Cursor's window) for the wrapper's own exit, its stdin left open: the code and the stderr.
    fn exit_unasked(&mut self) -> (Option<i32>, String) {
        let t = Instant::now();
        while t.elapsed() < LIVE_INIT_LIMIT {
            assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{}: interrupted", self.test);
            if let Some(status) = self.child.try_wait().expect("wait for ai-env-claude") {
                while self.next(Instant::now() + Duration::from_millis(50)).is_some() {}
                let err = self.stderr_now();
                return (status.code(), err);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{}: the wrapper did not end within {LIVE_INIT_LIMIT:?}", self.test);
    }

    /// What the chat put out, for [`sweep_live`]: its stdout lines and its stderr, once it exited.
    fn output(&mut self) -> std::process::Output {
        let status = self.child.wait().expect("ai-env-claude exited");
        if let Some(h) = self.stderr_reader.take() {
            let _ = h.join();
        }
        let stderr = self.stderr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        std::process::Output { status, stdout: self.stdout.clone(), stderr }
    }

    /// The wrapper ended if it still runs: continued first (a wrapper [`Chat::stop_for`] left stopped would never
    /// take the TERM), then SIGTERM (it detaches its spawn on its own), then SIGKILL 3 s later: its exit.
    fn end(&mut self) -> Option<std::process::ExitStatus> {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.signal(libc::SIGCONT);
            self.signal(libc::SIGTERM);
            let t = Instant::now();
            while matches!(self.child.try_wait(), Ok(None)) && t.elapsed() < Duration::from_secs(3) {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.child.kill();
        }
        self.child.wait().ok()
    }
}

impl Drop for Chat {
    fn drop(&mut self) {
        let _ = self.end();
    }
}

/// The census end row of the wrapper `pid` in the test's temporary root.
fn live_end_row(live: &Live, pid: u32) -> serde_json::Value {
    let rows = ai_env_cli::bridge::census::read_rows(&live.paths.census(), None).unwrap();
    rows.into_iter().rev().find(|r| r["pid"].as_u64() == Some(u64::from(pid)) && r["end"].as_u64().is_some()).unwrap_or_else(|| panic!("no census end row of the wrapper {pid}"))
}

/// The value of the note part `name` (`name:value`) of a census row.
fn note_part(row: &serde_json::Value, name: &str) -> Option<String> {
    row["note"].as_str()?.rsplit("; ").find_map(|p| p.strip_prefix(name).and_then(|rest| rest.strip_prefix(':'))).map(str::to_string)
}

/// The audit rows of `event` in the test's temporary root.
fn live_audit(live: &Live, event: &str) -> Vec<serde_json::Value> {
    ai_env_cli::bridge::audit::read_rows(&live.paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == event).collect()
}

/// A chat's end row, said: the parts part B's latency table records.
fn show_end(test: &str, row: &serde_json::Value) {
    let p = |k: &str| note_part(row, k).unwrap_or_else(|| "-".into());
    eprintln!(
        "{test}: exit {} {} vm_how:{} init_ms:{} legs:{} seed:{} transcript:{} fetch:{} credential:{} close_ms:{} end:{}",
        row["exit"],
        p("vm"),
        p("vm_how"),
        p("init_ms"),
        p("legs"),
        p("seed"),
        p("transcript"),
        p("fetch"),
        p("credential"),
        p("close_ms"),
        p("end")
    );
}

/// What every live chat's end must show: exit 0 and an EOF close (the wrapper's own exit within the close budget, by
/// the test's clock and by the census), the `initialize` answer's pid rewritten.
fn assert_closed_well(test: &str, live: &Live, chat: &Chat, code: Option<i32>, close: Duration) -> serde_json::Value {
    let row = live_end_row(live, chat.pid());
    show_end(test, &row);
    assert_eq!(code, Some(0), "{test}: the wrapper's exit");
    assert!(close.as_millis() <= u128::from(CLOSE_BUDGET_MS), "{test}: the wrapper exited {} ms after its stdin's close (budget {CLOSE_BUDGET_MS} ms)", close.as_millis());
    assert_eq!(note_part(&row, "end").as_deref(), Some("eof"), "{test}");
    assert!(note_part(&row, "close_ms").and_then(|ms| ms.parse::<u64>().ok()).is_some_and(|ms| ms <= CLOSE_BUDGET_MS), "{test}: the census's close_ms");
    assert_eq!(note_part(&row, "pid_rewrite").as_deref(), Some("ok"), "{test}");
    row
}

/// T8.2 and T8.3 live: a chat on a fresh VM (one Touch ID) seeds the fixture
/// at its identical path; a Bash tool call (allowed, as the permission prompt's
/// button would) prints aarch64, uid 1000 and that path; `initialize` came
/// within the cold budget, and the wrapper exits 0 within 1.5 s of its stdin's
/// close; no setup-token in the clear anywhere. Two Touch IDs: the chat, and
/// the purge of its S3 objects ([`PurgeTranscripts`], S10 F1).
#[test]
#[ignore = "live, starts a MicroVM and asks the model (two Touch IDs: the chat, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
fn live_wrapper_session_answers_ok_on_a_fresh_vm() {
    const TEST: &str = "live_wrapper_session_answers_ok_on_a_fresh_vm";
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-fresh");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    let init = chat.initialize();
    let turn = chat.turn("Run exactly this command with your Bash tool, then reply with its output only: uname -m; id -u; pwd");
    let (code, close) = chat.close();
    eprintln!("{TEST}: initialize answered after {} ms; the turn took {} ms, tools used {:?}, permission asked for {:?}", init.as_millis(), turn.ms, turn.used, turn.asked);
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert!(turn.used.iter().any(|t| t == "Bash"), "{TEST}: claude made no Bash call: {:?}", turn.used);
    let out = &turn.tool_output;
    assert!(out.lines().any(|l| l.trim() == "aarch64"), "{TEST}: uname -m: {out}");
    assert!(out.lines().any(|l| l.trim() == "1000"), "{TEST}: id -u: {out}");
    assert!(out.lines().any(|l| l.trim() == ws.display().to_string()), "{TEST}: pwd, the identical path {}: {out}", ws.display());
    assert_eq!(note_part(&row, "vm_how").as_deref(), Some("started"), "{TEST}");
    assert_eq!(note_part(&row, "seed").as_deref(), Some("seeded"), "{TEST}");
    let init_ms: u128 = note_part(&row, "init_ms").and_then(|ms| ms.parse().ok()).expect("init_ms");
    assert!(init_ms <= INIT_COLD_BUDGET_MS, "{TEST}: cold initialize {init_ms} ms over its budget {INIT_COLD_BUDGET_MS} ms (tree A: the legs say where)");
    assert!(note_part(&row, "legs").is_some_and(|l| l.starts_with("touchid=")), "{TEST}: the Touch ID leg");
    let out = chat.output();
    sweep_live(&live, &[&out], &[]);
}

/// A second chat in the same workspace reuses the first one's VM (kept
/// running: `[vm] suspend_on_close = false`) and its token: one delivery for
/// both, the second spawn naming the VM's copy (the census's `credential:`
/// of the second is `cached`, though a current combined.env's one Touch ID
/// brought the token along with the runtime key: it went unused). Three Touch
/// IDs: one per wrapper process (D1), and the purge of both chats' S3 objects
/// (one `session forget --purge` of them all, S10 F1).
#[test]
#[ignore = "live, starts a MicroVM and asks the model (three Touch IDs: two chats, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
fn live_wrapper_warm_session_reuses_the_vm_and_its_token() {
    const TEST: &str = "live_wrapper_warm_session_reuses_the_vm_and_its_token";
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[("suspend_on_close", toml::Value::Boolean(false)), ("reuse_per_workspace", toml::Value::Boolean(true))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-warm");
    let mut rows = Vec::new();
    let mut outs = Vec::new();
    for round in 1..=2 {
        let mut chat = Chat::open(TEST, &live, &ws, &[]);
        chat.initialize();
        let turn = chat.turn("Reply with exactly OK");
        assert_eq!(turn.result["is_error"], false, "{TEST}: round {round}: {}", turn.result);
        let (code, close) = chat.close();
        rows.push(assert_closed_well(TEST, &live, &chat, code, close));
        outs.push(chat.output());
    }
    let vm = note_part(&rows[0], "vm").expect("the first chat's VM");
    assert_eq!(note_part(&rows[0], "vm_how").as_deref(), Some("started"), "{TEST}");
    assert_eq!((note_part(&rows[1], "vm").as_deref(), note_part(&rows[1], "vm_how").as_deref()), (Some(vm.as_str()), Some("reused")), "{TEST}: the second chat's VM");
    assert_eq!(note_part(&rows[1], "credential").as_deref(), Some("cached"), "{TEST}: the second chat's CLI got the VM's copy");
    let warm_ms: u128 = note_part(&rows[1], "init_ms").and_then(|ms| ms.parse().ok()).expect("init_ms");
    eprintln!("{TEST}: warm initialize {warm_ms} ms (budget {INIT_WARM_BUDGET_MS} ms, the Touch ID inside it; not judged here: the init-wrapper probe reads the operator's census, never this temporary root's)");
    let delivered = live_audit(&live, "credential_deliver").iter().filter(|r| r["detail"]["id"] == vm.as_str()).count();
    assert_eq!(delivered, 1, "{TEST}: one delivery for the two chats");
    sweep_live(&live, &outs.iter().collect::<Vec<_>>(), &[]);
}

/// Code-out live: after a chat seeded the fixture (its VM kept running), a
/// commit and then an uncommitted edit made in the VM's checkout as the agent
/// (`vm exec`, so the result is the test's, not the model's) come to the Mac
/// with `box fetch --wip`: `refs/remotes/box/main` at the VM's commit, a
/// `box/wip/*` ref holding the edit, the Mac's HEAD and worktree untouched.
/// Four Touch IDs: the chat, `vm exec`, `box fetch`, the purge (S10 F1).
#[test]
#[ignore = "live, starts a MicroVM and asks the model (four Touch IDs: the chat, vm exec, box fetch, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
fn live_wrapper_box_fetch_sees_a_vm_commit_and_its_wip() {
    const TEST: &str = "live_wrapper_box_fetch_sees_a_vm_commit_and_its_wip";
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[("suspend_on_close", toml::Value::Boolean(false))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-codeout");
    let mac_head = fixture_git(&ws, &["rev-parse", "HEAD"]);
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    chat.turn("Reply with exactly OK");
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    let vm = note_part(&row, "vm").expect("the chat's VM");
    let path = ws.display().to_string();
    let script = "printf 'made in the VM\\n' > vm-commit.txt && git add vm-commit.txt && git -c user.name=ai-env-live -c user.email=live@ai-env.invalid -c commit.gpgsign=false commit -q -m 'a commit made in the VM' && git rev-parse HEAD && printf 'uncommitted in the VM\\n' > README.md";
    let exec = ai_env_live(&live, &["vm", "exec", &vm, "--cwd", &path, "--", "sh", "-c", script]);
    assert_eq!(exec.status.code(), Some(0), "{TEST}: vm exec");
    let vm_commit = String::from_utf8_lossy(&exec.stdout).trim().to_string();
    assert_eq!(vm_commit.len(), 40, "{TEST}: the VM's commit id: {vm_commit:?}");
    let fetch = ai_env_live(&live, &["box", "fetch", &path, "--wip", "--json"]);
    assert_eq!(fetch.status.code(), Some(0), "{TEST}: box fetch");
    assert_eq!(fixture_git(&ws, &["rev-parse", "refs/remotes/box/main"]), vm_commit, "{TEST}: box/main is the VM's commit");
    let wips = fixture_git(&ws, &["for-each-ref", "--sort=-refname", "--format=%(refname)", "refs/remotes/box/wip/"]);
    let newest = wips.lines().next().unwrap_or_else(|| panic!("{TEST}: no box/wip ref"));
    assert_eq!(fixture_git(&ws, &["show", &format!("{newest}:README.md")]), "uncommitted in the VM", "{TEST}: the snapshot holds the edit");
    assert_eq!(fixture_git(&ws, &["rev-parse", "HEAD"]), mac_head, "{TEST}: the Mac's HEAD");
    assert_eq!(fixture_git(&ws, &["status", "--porcelain"]), "", "{TEST}: the Mac's worktree");
    let out = chat.output();
    sweep_live(&live, &[&out, &exec, &fetch], &[]);
}

/// T8.5 live: a word told in a chat is recalled after its VM was terminated:
/// the reopened chat (`--resume` of its session) starts a new VM, its
/// transcript is restored there from S3 before the spawn
/// (`transcript:restored`, a `transcript_pull` audit row written), and the
/// conversation goes on. Four Touch IDs: two chats, the terminate and the
/// purge (S10 F1).
#[test]
#[ignore = "live, starts two MicroVMs and asks the model (four Touch IDs: two chats, the terminate, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
fn live_wrapper_resume_into_a_new_vm_continues_the_conversation() {
    const TEST: &str = "live_wrapper_resume_into_a_new_vm_continues_the_conversation";
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[("suspend_on_close", toml::Value::Boolean(false))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-resume");
    let word = format!("lantern{}", uuid::Uuid::now_v7().simple().to_string().chars().rev().take(4).collect::<String>());
    let mut first = Chat::open(TEST, &live, &ws, &[]);
    first.initialize();
    first.turn(&format!("Remember this word for later: {word}. Reply with exactly OK"));
    let (code, close) = first.close();
    let row = assert_closed_well(TEST, &live, &first, code, close);
    let (vm1, session) = (note_part(&row, "vm").expect("the first VM"), first.session.clone().expect("the chat's session id"));
    let terminate = ai_env_live(&live, &["vm", "terminate", &vm1, "--yes"]);
    assert_eq!(terminate.status.code(), Some(0), "{TEST}: vm terminate");
    let resume = format!("--resume={session}");
    let mut second = Chat::open(TEST, &live, &ws, &[&resume]);
    second.initialize();
    let turn = second.turn("Which word did I ask you to remember? Reply with the word only.");
    let (code, close) = second.close();
    let row = assert_closed_well(TEST, &live, &second, code, close);
    let answer = turn.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer {answer:?} lacks the word");
    assert_eq!(second.session.as_deref(), Some(session.as_str()), "{TEST}: the same session id");
    let vm2 = note_part(&row, "vm").expect("the second VM");
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    assert_eq!((note_part(&row, "vm_how").as_deref(), note_part(&row, "transcript").as_deref()), (Some("started"), Some("restored")), "{TEST}");
    assert!(live_audit(&live, "transcript_pull").iter().any(|r| r["detail"]["outcome"] == "written" && r["detail"]["vm"] == vm2.as_str()), "{TEST}: the pull into the new VM is audited");
    let (a, b) = (first.output(), second.output());
    sweep_live(&live, &[&a, &b, &terminate], &[]);
}

/// A secret in the workspace is caught before anything leaves the Mac: an
/// untracked file holding an access-key shape (built here; the fixture is
/// removed on every path, `RemoveOnDrop`) refuses the seed at P1, the wrapper
/// exits 9 with the finding's line (never the value), and no VM was asked for
/// (no RunMicrovm: no VM row, no `vm_run`). At most one Touch ID (the dialog
/// may close with the refusal); no session was registered, so nothing is
/// purged ([`PurgeTranscripts`] runs no command).
#[test]
#[ignore = "live, no VM expected (at most one Touch ID): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make test-aws CRED=1"]
fn live_wrapper_seed_refuses_a_planted_secret_before_any_vm() {
    const TEST: &str = "live_wrapper_seed_refuses_a_planted_secret_before_any_vm";
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-secret");
    // The planted value never outlives the test: the fixture goes on every path, after the chat (made later) ended.
    let _planted = RemoveOnDrop(ws.clone());
    let key = format!("{}{}", "AKIA", "Q7ZT".repeat(4));
    std::fs::write(ws.join("deploy.conf"), format!("aws_access_key_id = {key}\n")).unwrap();
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.send(&serde_json::json!({"type": "control_request", "request_id": "live-init", "request": {"subtype": "initialize"}}));
    let (code, err) = chat.exit_unasked();
    eprintln!("{TEST}: exit {code:?}; the last line: {}", err.lines().last().unwrap_or_default());
    assert_eq!(code, Some(9), "{TEST}: {err}");
    assert!(err.lines().last().is_some_and(|l| l.starts_with("ai-env-claude: ")), "{TEST}: one ai-env-claude line last: {err}");
    assert!(!err.contains(&key[4..]), "{TEST}: the value is never shown");
    assert!(vm_rows::list_rows(&live.paths).unwrap().is_empty(), "{TEST}: no VM row: nothing was started");
    assert!(live_audit(&live, "vm_run").is_empty(), "{TEST}: no RunMicrovm");
    let row = live_end_row(&live, chat.pid());
    assert_eq!(note_part(&row, "end").as_deref(), Some("spawn_failed"), "{TEST}");
    let out = chat.output();
    sweep_live(&live, &[&out], &[&key]);
}

/// `make s8-smoke`'s body (T8.2's gate): three live chats in a fixture
/// workspace, each seeding (or keeping) the VM, one turn, its code-out fetch
/// recorded before the close, and the wrapper's exit 0 within 1.5 s; each
/// pass's record appended to `target/s8/smoke.jsonl`. One Touch ID per pass,
/// the test process's own, and one for the three chats' S3 objects, purged at
/// the end by one `session forget --purge` of them all (S10 F1): five.
#[test]
#[ignore = "live, starts a MicroVM and asks the model three times (five Touch IDs: the test process's runtime key, one per pass, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 make s8-smoke"]
fn live_wrapper_smoke() {
    const TEST: &str = "live_wrapper_smoke";
    if !cred_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-smoke");
    let records = std::fs::canonicalize(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/s8")).unwrap().join("smoke.jsonl");
    let mut outs = Vec::new();
    for pass in 1..=3 {
        let fetched = live_audit(&live, "codeout_fetch").len();
        let mut chat = Chat::open(TEST, &live, &ws, &[]);
        let init = chat.initialize();
        let turn = chat.turn("Reply with exactly OK");
        assert_eq!(turn.result["is_error"], false, "{TEST}: pass {pass}: {}", turn.result);
        // The end row counts the turn's code-out only once its report is in (plan section 11): wait for its row.
        let t = Instant::now();
        while live_audit(&live, "codeout_fetch").len() == fetched {
            assert!(t.elapsed() < Duration::from_secs(60), "{TEST}: pass {pass}: no codeout_fetch row within 60 s of the result");
            std::thread::sleep(Duration::from_millis(200));
        }
        let (code, close) = chat.close();
        let row = assert_closed_well(TEST, &live, &chat, code, close);
        let fetch = note_part(&row, "fetch").unwrap_or_default();
        let (ok, runs) = fetch.split_once('/').map(|(a, b)| (a.parse::<u32>().unwrap_or(0), b.parse::<u32>().unwrap_or(0))).unwrap_or((0, 0));
        let record = serde_json::json!({
            "pass": pass, "ts": ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now()), "exit": code, "close_ms": close.as_millis() as u64,
            "initialize_ms": init.as_millis() as u64, "turn_ms": turn.ms as u64, "vm": note_part(&row, "vm"), "vm_how": note_part(&row, "vm_how"),
            "init_ms": note_part(&row, "init_ms"), "legs": note_part(&row, "legs"), "seed": note_part(&row, "seed"), "fetch": fetch, "credential": note_part(&row, "credential"),
        });
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&records).unwrap();
            writeln!(f, "{record}").unwrap();
        }
        assert!(ok >= 1 && ok == runs, "{TEST}: pass {pass}: the code-out fetch {fetch:?}");
        assert!(note_part(&row, "seed").is_some(), "{TEST}: pass {pass}: the seed's word");
        eprintln!("s8-smoke: pass {pass} ok");
        outs.push(chat.output());
    }
    eprintln!("s8-smoke: 3/3 ok ({})", records.display());
    sweep_live(&live, &outs.iter().collect::<Vec<_>>(), &[]);
}

/// `ai-env egress suspend api.anthropic.com [--restore]` on the operator's real bridge root (the proxy is shared),
/// killed after 300 s.
fn egress_suspend_api(restore: bool) -> std::process::Output {
    let root = Paths::resolve().expect("the real bridge root").root;
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env"));
    c.args(["egress", "suspend", "api.anthropic.com"]);
    if restore {
        c.arg("--restore");
    }
    let child = c.env("AI_ENV_BRIDGE_DIR", root).env_remove("AI_ENV_BRIDGE_CONFIG").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("spawn ai-env");
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(300)) {
        Ok(out) => out.expect("ai-env output"),
        Err(_) => {
            let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            panic!("ai-env egress suspend did not finish within 300 s");
        }
    }
}

/// The API host's suspension on the proxy: lifted on drop unless `restore` already did it.
struct ApiHostSuspended {
    armed: bool,
}

impl ApiHostSuspended {
    fn suspend() -> ApiHostSuspended {
        let o = egress_suspend_api(false);
        let held = ApiHostSuspended { armed: true };
        assert!(o.status.success(), "egress suspend: {}", no_account(&String::from_utf8_lossy(&o.stderr)));
        held
    }

    fn restore(&mut self) {
        let o = egress_suspend_api(true);
        self.armed = !o.status.success();
        assert!(o.status.success(), "egress suspend --restore: {}", no_account(&String::from_utf8_lossy(&o.stderr)));
    }
}

impl Drop for ApiHostSuspended {
    fn drop(&mut self) {
        if self.armed {
            let o = egress_suspend_api(true);
            let _ = writeln!(std::io::stderr(), "guard: egress suspend api.anthropic.com --restore: exit {:?} — check with ai-env egress status", o.status.code());
        }
    }
}

/// L8's `AUTH_FAIL_BUDGET_MS` live: with the API host denied on the proxy
/// mid-session (`egress suspend`, lifted on every path), a turn ends by the
/// CLI's own retries within the budget, as an error result while the session
/// lives on (nothing was refused: never exit 5 or `credential_rejected`).
/// With AI_ENV_AWS_SLOW=1 too (about four minutes; four Touch IDs: the
/// chat's, the purge of its S3 objects (S10 F1), then the ops key's for the
/// suspension and again for its restore, each `egress suspend` its own
/// process; under `ai-env as ops` or `ai-env as deployer` the chat's and the
/// purge's alone, two).
#[test]
#[ignore = "live, about four minutes, denies api.anthropic.com on the proxy meanwhile (four Touch IDs: the chat's, the purge, the ops key's for the suspension and for its restore; the chat's and the purge alone, two, under ai-env as ops or as deployer): AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 AI_ENV_AWS_SLOW=1 make test-aws CRED=1 SLOW=1"]
fn live_wrapper_suspended_api_host_ends_the_turn_within_the_auth_fail_budget() {
    const TEST: &str = "live_wrapper_suspended_api_host_ends_the_turn_within_the_auth_fail_budget";
    if !cred_live() {
        return;
    }
    if std::env::var("AI_ENV_AWS_SLOW").as_deref() != Ok("1") {
        eprintln!("skipped: set AI_ENV_AWS_SLOW=1 too (make test-aws CRED=1 SLOW=1)");
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-wrapper-api-host");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let first = chat.turn("Reply with exactly OK");
    assert_eq!(first.result["is_error"], false, "{TEST}: the turn before the suspension: {}", first.result);
    let mut held = ApiHostSuspended::suspend();
    let turn = chat.turn("Reply with exactly OK");
    held.restore();
    eprintln!("{TEST}: the turn under the suspension ended after {} ms (budget {} ms): {}", turn.ms, ai_env_cli::bridge::authwatch::AUTH_FAIL_BUDGET_MS, scrub(&turn.result.to_string()).chars().take(400).collect::<String>());
    assert_eq!(turn.result["is_error"], true, "{TEST}: an error result");
    assert!(turn.ms <= u128::from(ai_env_cli::bridge::authwatch::AUTH_FAIL_BUDGET_MS), "{TEST}: {} ms over the budget", turn.ms);
    assert!(matches!(chat.child.try_wait(), Ok(None)), "{TEST}: the session lives on after the failed turn");
    let (code, close) = chat.close();
    let row = live_end_row(&live, chat.pid());
    show_end(TEST, &row);
    assert_ne!(code, Some(5), "{TEST}: nothing was refused");
    assert_ne!(note_part(&row, "end").as_deref(), Some("credential_rejected"), "{TEST}");
    assert!(close.as_millis() <= u128::from(CLOSE_BUDGET_MS), "{TEST}: the close took {} ms", close.as_millis());
    let out = chat.output();
    sweep_live(&live, &[&out], &[]);
}

// ---- S9: smart-HTTP, review, the push path and the S3 store, live (part B: B3 to B6) --------
//
// S9 wave 2 (G8). The smart-HTTP tests (`make test-aws`: AI_ENV_AWS_TESTS=1)
// run the real CLI in a temporary bridge root holding what a vpc VM's run and
// gate read ([`s9_world`]): `vm run --egress vpc --workspace` on a fixture
// under this checkout's `target/s8/` (a configured root must hold it, as for
// S8's), `box seed`, commits made in the VM as the agent (`vm exec`), then
// `box fetch` either way and `box review` (no AWS call, no Touch ID). One
// Touch ID per `ai-env vm` or `box` command that reaches AWS, and the test
// process's own once when it reads the service itself (`LIVE_CREDS`).
// `SessionVms` ends every VM whose row is in the temporary root. The re-mint
// after expiry needs AI_ENV_AWS_SLOW=1 and, in the test process's own
// environment, AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES (`make test-aws SLOW=1`
// sets 2): its 9418 tokens are minted in process, by `MintingTokens`.
// The S3 store's tests (`make test-aws S3=1`: AI_ENV_S3_TESTS=1) are chats
// of the real `ai-env-claude` in remote mode on S8's rig (`wrapper_world`,
// `Chat`; the setup-token sealed), on an image and a Mac past S9's cut-over:
// a chat's turns land in S3 and the Mac keeps the view; a reopen in a new VM
// restores from S3; a 1 GiB chat begun on the Mac is staged with `--warm`
// (restored into the VM its reopen takes) and round-trips (its rates printed,
// and claude's memory with it open); the Mac cannot read the VM's objects,
// nor write one.
// Each purges its chats' objects at its end (one `session forget <ids...>
// --purge` of them all, one Touch ID more: `PurgeTranscripts`, S10 F1).

use ai_env_cli::bridge::dataplane::{HttpsEndpoint as DataEndpoint, MintingTokens, TokenSource};
use ai_env_cli::bridge::gitsmart::Client as SmartHttp;
use ai_env_cli::wire::workspace::{ObjectFormat, APP_PORT as S9_APP_PORT, CODE_PORT as S9_CODE_PORT};

/// Whether the S3 store's live tests run: [`live`], and AI_ENV_S3_TESTS=1 (`make test-aws S3=1`).
fn s3_live() -> bool {
    if !live() {
        return false;
    }
    if std::env::var("AI_ENV_S3_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_S3_TESTS=1 too (make test-aws S3=1) for the S3 store's chats");
    false
}

/// [`live_world`] with what a vpc VM's run and gate read (the egress
/// records and the dns-path rows, as [`cred_world`] copies them; no
/// setup-token) and `[vm] max_duration_s = 900`.
fn s9_world() -> Live {
    let mut live = live_world();
    let real = Paths::resolve().expect("the real bridge root");
    for (from, to) in [(real.egress_verified(), live.paths.egress_verified()), (real.probes(), live.paths.probes())] {
        if from.exists() {
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(&from, &to).unwrap();
        }
    }
    let mut doc: toml::Table = toml::from_str(&std::fs::read_to_string(&live.paths.config).unwrap()).expect("the copied bridge.toml");
    let table = doc.entry("vm").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    table.as_table_mut().expect("[vm] is a table").insert("max_duration_s".into(), toml::Value::Integer(900));
    std::fs::write(&live.paths.config, toml::to_string(&doc).unwrap()).unwrap();
    live.cfg = BridgeConfig::load(&live.paths).unwrap().expect("bridge.toml");
    live
}

/// A git command line as the agent's own, for a commit made in the VM: the fixture's author, no signing.
const VM_GIT: &str = "git -c user.name=ai-env-live -c user.email=live@ai-env.invalid -c commit.gpgsign=false";

/// The fixture `ws`'s vpc VM (`vm run --workspace`), seeded (`box seed`): its id. Two Touch IDs.
fn s9_seeded_vm(test: &str, live: &Live, ws: &str) -> String {
    let run = ai_env_live(live, &["vm", "run", "--egress", "vpc", "--workspace", ws, "--json"]);
    assert_eq!(run.status.code(), Some(0), "{test}: vm run");
    let v: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap_or_else(|e| panic!("{test}: vm run --json: {e}"));
    let id = v["id"].as_str().unwrap_or_else(|| panic!("{test}: no id in {v}")).to_string();
    let (code, seeded, _) = box_json(test, live, &["seed", ws]);
    assert_eq!((code, seeded["outcome"].as_str(), seeded["vm"].as_str()), (Some(0), Some("seeded"), Some(id.as_str())), "{test}: {seeded}");
    id
}

/// `sh -c <script>` in the VM `vm` at `path`, as the agent (`vm exec`, one Touch ID): its stdout trimmed, after exit 0.
fn vm_sh(test: &str, live: &Live, vm: &str, path: &str, script: &str) -> (String, std::process::Output) {
    let out = ai_env_live(live, &["vm", "exec", vm, "--cwd", path, "--", "sh", "-c", script]);
    assert_eq!(out.status.code(), Some(0), "{test}: vm exec: {}", String::from_utf8_lossy(&out.stdout));
    (String::from_utf8_lossy(&out.stdout).trim().to_string(), out)
}

/// `ai-env box <args> --json` in the test's root: its exit and its JSON document.
fn box_json(test: &str, live: &Live, args: &[&str]) -> (Option<i32>, serde_json::Value, std::process::Output) {
    let mut all = vec!["box"];
    all.extend_from_slice(args);
    all.push("--json");
    let out = ai_env_live(live, &all);
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{test}: box {args:?} --json ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code(), v, out)
}

/// A fetch's `report.<key>` (`promoted`, `quarantined`): full ref name to commit.
fn report_refs(v: &serde_json::Value, key: &str) -> BTreeMap<String, String> {
    v["report"][key].as_object().map(|m| m.iter().filter_map(|(r, id)| id.as_str().map(|id| (r.clone(), id.to_string()))).collect()).unwrap_or_default()
}

/// T9.2 live (B3): smart-HTTP promotes what `/codeout` promotes. In a seeded
/// vpc VM the agent commits on `main` and on a branch of its own; `box fetch`
/// (`/codeout`) promotes both heads at the VM's tips; with those refs deleted
/// on the Mac, `box fetch --smart-http` promotes exactly the same map; the
/// audit names each fetch's way. Five Touch IDs: vm run, box seed, vm exec,
/// the two fetches.
#[test]
#[ignore = "live, starts a vpc MicroVM (five Touch IDs: vm run, box seed, vm exec, two box fetch): AI_ENV_AWS_TESTS=1 make test-aws"]
fn live_box_fetch_smart_http_matches_codeout() {
    const TEST: &str = "live_box_fetch_smart_http_matches_codeout";
    if !live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s9_world();
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s9-smart-http");
    let path = ws.display().to_string();
    let vm = s9_seeded_vm(TEST, &live, &path);
    let script = format!(
        "git checkout -q -b feature && printf 'a feature\\n' > feature.txt && git add feature.txt && {VM_GIT} commit -q -m 'a feature' && git checkout -q main && printf 'on main\\n' > main.txt && git add main.txt && {VM_GIT} commit -q -m 'on main' && git for-each-ref --format='%(refname) %(objectname)' refs/heads"
    );
    let (heads, exec) = vm_sh(TEST, &live, &vm, &path, &script);
    let heads: BTreeMap<String, String> = heads.lines().filter_map(|l| l.split_once(' ')).map(|(r, id)| (r.replacen("refs/heads/", "refs/remotes/box/", 1), id.to_string())).collect();
    assert_eq!(heads.len(), 2, "{TEST}: main and feature in the VM: {heads:?}");
    let (code, codeout, a) = box_json(TEST, &live, &["fetch", &path]);
    assert_eq!((code, codeout["via"].as_str()), (Some(0), Some("codeout")), "{TEST}: {codeout}");
    let promoted = report_refs(&codeout, "promoted");
    for (r, id) in &heads {
        assert_eq!(promoted.get(r), Some(id), "{TEST}: /codeout promoted {r} at the VM's tip: {codeout}");
    }
    for r in promoted.keys() {
        fixture_git(&ws, &["update-ref", "-d", r]);
    }
    let (code, smart, b) = box_json(TEST, &live, &["fetch", &path, "--smart-http"]);
    assert_eq!((code, smart["via"].as_str()), (Some(0), Some("smart-http")), "{TEST}: {smart}");
    assert_eq!(report_refs(&smart, "promoted"), promoted, "{TEST}: smart-HTTP promotes what /codeout promoted");
    let vias: Vec<String> = live_audit(&live, "codeout_fetch").iter().filter_map(|r| r["detail"]["via"].as_str().map(str::to_string)).collect();
    assert_eq!(vias, ["codeout", "smart-http"], "{TEST}: each fetch audited with its way");
    eprintln!("{TEST}: both ways promoted {} refs: {:?}", promoted.len(), promoted.keys().collect::<Vec<_>>());
    sweep_live(&live, &[&exec, &a, &b], &[]);
}

/// Hands out, for whatever port is asked, a `Port(8080)` token minted for
/// the VM and labelled with the asked port: on 9418, the token of the wrong
/// port. Counts its mints and forgets.
struct WrongPortTokens<'a> {
    api: &'a SdkMicrovmApi,
    vm: String,
    minted: std::sync::atomic::AtomicU32,
    forgot: std::sync::atomic::AtomicU32,
}

impl TokenSource for WrongPortTokens<'_> {
    async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
        self.minted.fetch_add(1, Ordering::SeqCst);
        let t = self.api.create_auth_token(&self.vm, 5, S9_APP_PORT).await?;
        Ok(AuthToken { port, ..t })
    }

    fn forget(&self, _port: u16) {
        self.forgot.fetch_add(1, Ordering::SeqCst);
    }
}

/// T9.2 live (B3): a token of the wrong port on the code port is refused by
/// the endpoint twice: smart-HTTP's advertisement sends with an 8080 token
/// on 9418, is refused (403, `x-aws-proxy-error: UNAUTHORIZED`, as S4
/// measured a wrong-port token), forgets it, mints once more, is refused
/// again, and stops: `TokenRejected` on 9418, exit 7. One Touch ID (the test
/// process's runtime key).
#[tokio::test]
#[ignore = "live, starts a MicroVM (one Touch ID): AI_ENV_AWS_TESTS=1 make test-aws"]
async fn live_smart_http_wrong_port_token_403_twice() {
    if !live() {
        return;
    }
    let live = live_world();
    let guard = VmGuard::new(&live);
    let api = connect(&live.creds).await;
    let ep = HttpsEndpoint::new().unwrap();
    let (_, vm, _) = start(&api, &ep, &live, &guard, &test_plan(&live, None)).await;
    read_health(&api, &ep, &live.paths, &vm.id, Backoff::HEALTH).await.unwrap();
    let row = vm_rows::read_row(&live.paths, &vm.id).unwrap().expect("the VM's row");
    let target = AgentTarget::from_row(&row).unwrap();
    let tokens = WrongPortTokens { api: &api, vm: vm.id.clone(), minted: std::sync::atomic::AtomicU32::new(0), forgot: std::sync::atomic::AtomicU32::new(0) };
    let dp = DataEndpoint::new(&VmKnobs::default()).unwrap();
    let client = SmartHttp { api: &api, tokens: &tokens, git: &dp, target: &target };
    let e = client.advertise(ObjectFormat::Sha1).await.expect_err("a token of the wrong port never passes");
    eprintln!("live_smart_http_wrong_port_token_403_twice: {}", no_account(&e.to_string()));
    assert!(matches!(&e, BridgeError::TokenRejected { port: S9_CODE_PORT, status: 403, proxy_error: Some(p) } if p == "UNAUTHORIZED"), "{}", no_account(&e.to_string()));
    assert_eq!((tokens.minted.load(Ordering::SeqCst), tokens.forgot.load(Ordering::SeqCst)), (2, 1), "refused, forgotten, minted once more, refused again");
    assert_eq!(CliError::from(e).exit_code(), 7);
}

/// T9.2 live (B3, SLOW): a 9418 token that expired is minted again, and
/// smart-HTTP goes on. With the code-token knob (2 minutes under `make
/// test-aws SLOW=1`), a seeded VM's advertisement is asked through
/// `MintingTokens`, which records each mint's expiry in the VM's row; past
/// that expiry the next advertisement mints a new token (the row's 9418
/// expiry moves on) and is answered. Three Touch IDs: vm run, box seed, the
/// test process's runtime key.
#[tokio::test]
#[ignore = "live, about four minutes, starts a vpc MicroVM (three Touch IDs): AI_ENV_AWS_TESTS=1 AI_ENV_AWS_SLOW=1 AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2 (make test-aws SLOW=1)"]
async fn live_smart_http_remints_after_expiry() {
    const TEST: &str = "live_smart_http_remints_after_expiry";
    if !live() {
        return;
    }
    if std::env::var("AI_ENV_AWS_SLOW").as_deref() != Ok("1") {
        eprintln!("skipped: set AI_ENV_AWS_SLOW=1 (make test-aws SLOW=1) for the re-mint after a code token's expiry");
        return;
    }
    let Some(minutes) = ai_env_cli::bridge::lab::vm_knobs().code_token_minutes().filter(|m| *m <= 3) else {
        panic!("{TEST}: set AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES to 1, 2 or 3 in the test's environment (make test-aws SLOW=1 sets 2)");
    };
    let _signals = Interrupts::catch();
    let live = s9_world();
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s9-remint");
    let path = ws.display().to_string();
    let vm = s9_seeded_vm(TEST, &live, &path);
    let api = connect(&live.creds).await;
    let row = vm_rows::read_row(&live.paths, &vm).unwrap().expect("the VM's row");
    let target = AgentTarget::from_row(&row).unwrap();
    let dp = DataEndpoint::new(&VmKnobs::default()).unwrap();
    let tokens = MintingTokens::new(&api, &live.paths, &vm, false);
    let client = SmartHttp { api: &api, tokens: &tokens, git: &dp, target: &target };
    let expiry = || vm_rows::read_row(&live.paths, &vm).unwrap().and_then(|r| r.token_expiries.get("9418").copied()).unwrap_or_else(|| panic!("{TEST}: no 9418 token's expiry in the row"));
    let first = client.advertise(ObjectFormat::Sha1).await.unwrap_or_else(|e| panic!("{TEST}: {}", no_account(&e.to_string())));
    let (minted, now) = (expiry(), ai_env_cli::wire::time::unix_now());
    assert!(minted <= now + u64::from(minutes) * 60 + 5, "{TEST}: the 9418 token lasts the knob's {minutes} minutes: it expires at {minted}, now {now}");
    tokio::time::sleep(Duration::from_secs(minted.saturating_sub(now) + 15)).await;
    assert!(ai_env_cli::wire::time::unix_now() > minted, "{TEST}: the first token has expired");
    let second = client.advertise(ObjectFormat::Sha1).await.unwrap_or_else(|e| panic!("{TEST}: after the expiry: {}", no_account(&e.to_string())));
    let again = expiry();
    eprintln!("{TEST}: a {minutes}-minute 9418 token expired at {minted}; the next advertisement minted one to {again}");
    assert!(again > minted, "{TEST}: a new token was minted once the first expired");
    assert_eq!(first, second, "{TEST}: the same advertisement");
}

/// `ai-env box review <rev> --repo <ws> --json` (no AWS call, no Touch ID): its exit and JSON.
fn review(test: &str, live: &Live, ws: &str, rev: &str) -> (Option<i32>, serde_json::Value, std::process::Output) {
    box_json(test, live, &["review", rev, "--repo", ws])
}

/// T9.3 live (B4): the review loop, and no tag leaks. In a seeded vpc VM
/// the agent commits and tags; `box fetch --smart-http` brings the commit
/// and never the tag, and `box review` passes it. A commit holding an
/// access-key shape (built here) comes in quarantined (exit 9), and `box
/// review` of it exits 9 naming the file and line, never the value. The
/// agent drops that commit and commits clean: the next fetch moves
/// `box/main` there, and its review passes. No `refs/tags/*` ever came to
/// the Mac; nothing was pushed anywhere. Nine Touch IDs: the test process's
/// runtime key, vm run, box seed, three vm exec, three box fetch (the reviews
/// take none).
#[test]
#[ignore = "live, starts a vpc MicroVM (nine Touch IDs: the test process's runtime key, vm run, box seed, three vm exec, three box fetch): AI_ENV_AWS_TESTS=1 make test-aws"]
fn live_review_loop_and_tag_leak() {
    const TEST: &str = "live_review_loop_and_tag_leak";
    if !live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s9_world();
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s9-review");
    let path = ws.display().to_string();
    let vm = s9_seeded_vm(TEST, &live, &path);
    let mut outs = Vec::new();
    let (clean, o) = vm_sh(TEST, &live, &vm, &path, &format!("printf 'clean\\n' > clean.txt && git add clean.txt && {VM_GIT} commit -q -m 'a clean change' && git tag v-leak && git rev-parse HEAD"));
    outs.push(o);
    let (code, fetched, o) = box_json(TEST, &live, &["fetch", &path, "--smart-http"]);
    outs.push(o);
    assert_eq!((code, report_refs(&fetched, "promoted").get("refs/remotes/box/main")), (Some(0), Some(&clean)), "{TEST}: {fetched}");
    let (code, reviewed, o) = review(TEST, &live, &path, "refs/remotes/box/main");
    outs.push(o);
    assert_eq!((code, reviewed["verdict"].as_str()), (Some(0), Some("pass")), "{TEST}: {reviewed}");
    // A key shape, built here: the fetch quarantines it, the review names where it is.
    let key = format!("{}{}", "AKIA", "Q7ZT".repeat(4));
    let (planted, o) = vm_sh(TEST, &live, &vm, &path, &format!("printf 'aws_access_key_id = %s\\n' {key} > leak.txt && git add leak.txt && {VM_GIT} commit -q -m 'a planted key' && git rev-parse HEAD"));
    outs.push(o);
    let (code, fetched, o) = box_json(TEST, &live, &["fetch", &path, "--smart-http"]);
    outs.push(o);
    assert_eq!((code, report_refs(&fetched, "quarantined").get("refs/remotes/box-quarantine/main")), (Some(9), Some(&planted)), "{TEST}: {fetched}");
    let (code, reviewed, o) = review(TEST, &live, &path, "refs/remotes/box-quarantine/main");
    outs.push(o);
    assert_eq!((code, reviewed["verdict"].as_str()), (Some(9), Some("findings")), "{TEST}: {reviewed}");
    let findings = reviewed["findings"].as_array().cloned().unwrap_or_default();
    assert!(findings.iter().any(|f| f["path"] == "leak.txt" && f["line"] == 1 && f["commit"] == planted.as_str()), "{TEST}: the finding names leak.txt:1 in the planted commit: {reviewed}");
    // The loop: the agent drops the commit and commits clean.
    let (fixed, o) = vm_sh(TEST, &live, &vm, &path, &format!("git reset -q --hard HEAD~1 && printf 'fixed\\n' > fixed.txt && git add fixed.txt && {VM_GIT} commit -q -m 'without the key' && git rev-parse HEAD"));
    outs.push(o);
    let (code, fetched, o) = box_json(TEST, &live, &["fetch", &path, "--smart-http"]);
    outs.push(o);
    assert_eq!((code, report_refs(&fetched, "promoted").get("refs/remotes/box/main")), (Some(0), Some(&fixed)), "{TEST}: {fetched}");
    let (code, reviewed, o) = review(TEST, &live, &path, "refs/remotes/box/main");
    outs.push(o);
    assert_eq!((code, reviewed["verdict"].as_str()), (Some(0), Some("pass")), "{TEST}: the fixed range passes: {reviewed}");
    assert_eq!(fixture_git(&ws, &["for-each-ref", "refs/tags", "refs/remotes/box/tags", "refs/remotes/box-quarantine/tags"]), "", "{TEST}: the VM's tag never reached the Mac");
    assert_eq!(fixture_git(&ws, &["remote"]), "", "{TEST}: the fixture has no remote: nothing could be pushed");
    sweep_live(&live, &outs.iter().collect::<Vec<_>>(), &[key.as_str()]);
}

/// T9.4 live (B5): the VM has no push path. In a seeded vpc VM, as the
/// agent: `git push` finds no destination; there is no `~/.ssh`,
/// `~/.config/gh` or `~/.git-credentials`; git's user is `claude-agent`
/// (the image's); and github.com is refused at the egress proxy (its
/// CONNECT answered 403). Four Touch IDs: the test process's runtime key,
/// vm run, box seed, vm exec.
#[test]
#[ignore = "live, starts a vpc MicroVM (four Touch IDs: the test process's runtime key, vm run, box seed, vm exec): AI_ENV_AWS_TESTS=1 make test-aws"]
fn live_vm_has_no_push_path() {
    const TEST: &str = "live_vm_has_no_push_path";
    if !live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s9_world();
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s9-no-push");
    let path = ws.display().to_string();
    let vm = s9_seeded_vm(TEST, &live, &path);
    let script = "git push 2>&1; echo \"push=$?\"; for p in \"$HOME/.ssh\" \"$HOME/.config/gh\" \"$HOME/.git-credentials\"; do if [ -e \"$p\" ]; then echo \"present=$p\"; fi; done; \
                  echo \"user=$(git config user.name)\"; echo \"github=$(curl -s -o /dev/null --max-time 20 -w '%{http_connect} %{http_code}' https://github.com/)\"";
    let (said, out) = vm_sh(TEST, &live, &vm, &path, script);
    eprintln!("{TEST}:\n{said}");
    assert!(said.contains("No configured push destination"), "{TEST}: git push: {said}");
    assert!(said.lines().any(|l| l.starts_with("push=") && l != "push=0"), "{TEST}: the push failed: {said}");
    assert!(!said.lines().any(|l| l.starts_with("present=")), "{TEST}: a credential store in the VM: {said}");
    assert!(said.lines().any(|l| l == "user=claude-agent"), "{TEST}: git's user: {said}");
    assert!(said.lines().any(|l| l.starts_with("github=403 ")), "{TEST}: github.com refused at the proxy: {said}");
    sweep_live(&live, &[&out], &[]);
}

/// The Mac's projects directory, where Cursor's chats and a remote chat's view live.
fn mac_projects() -> std::path::PathBuf {
    std::env::var_os("CLAUDE_CONFIG_DIR").map_or_else(|| std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".claude"), std::path::PathBuf::from).join("projects")
}

/// The manifest the Mac keeps of `session`'s transcript in S3 (`state/transcripts/<sid>/manifest.toml`).
fn s3_manifest(test: &str, live: &Live, session: &str) -> toml::Table {
    let path = live.paths.transcript_manifest(session);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{test}: {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("{test}: {}: {e}", path.display()))
}

/// The manifest's parts: (key, version id) each.
fn manifest_parts(m: &toml::Table) -> Vec<(String, Option<String>)> {
    m.get("parts").and_then(toml::Value::as_array).map(|parts| parts.iter().filter_map(|p| Some((p.get("key")?.as_str()?.to_string(), p.get("version_id").and_then(toml::Value::as_str).map(str::to_string)))).collect()).unwrap_or_default()
}

/// Whether the manifest `m` of `session` lists a part of the VM's
/// (`v1/<sid>/vm/…`, with a version id) that holds bytes past `after`.
fn vm_part_past(m: &toml::Table, session: &str, after: u64) -> bool {
    let prefix = format!("v1/{session}/vm/");
    let num = |p: &toml::Value, k: &str| p.get(k).and_then(toml::Value::as_integer).and_then(|n| u64::try_from(n).ok());
    m.get("parts").and_then(toml::Value::as_array).is_some_and(|parts| {
        parts.iter().any(|p| {
            p.get("key").and_then(toml::Value::as_str).is_some_and(|k| k.starts_with(&prefix))
                && p.get("version_id").and_then(toml::Value::as_str).is_some_and(|v| !v.is_empty())
                && num(p, "from").zip(num(p, "len")).is_some_and(|(from, len)| from.saturating_add(len) > after)
        })
    })
}

/// How long a turn's sync may take to commit after its result, the chat
/// open: the code-out trigger hands a tail, fetches and captures the
/// settings before it syncs.
const LIVE_SYNC_LIMIT: Duration = Duration::from_secs(60);
/// How often [`Chat::wait_for_sync`] reads the manifest.
const LIVE_SYNC_POLL: Duration = Duration::from_millis(500);

impl Chat {
    /// After a turn's result, the chat left open: wait until the Mac's
    /// manifest of its session (`chat.session`, the turn's `system/init`'s)
    /// lists a part of the VM's (`v1/<sid>/vm/…`, with its version) that
    /// holds bytes past `after`, what the manifest committed before the turn
    /// (0 before any): the turn's own sync committed it. The code-out
    /// trigger runs that sync after the result, and a close before the
    /// trigger starts it starts none of it (these tests turn the closing
    /// suspend's tail off). The manifest is read every [`LIVE_SYNC_POLL`] (a
    /// file of the Mac's: no Touch ID) and the chat's lines meanwhile; how
    /// long it took is printed. Past [`LIVE_SYNC_LIMIT`], or once the wrapper
    /// exits, the test fails naming what is missing: the manifest, or such a
    /// part. The manifest's committed length (the next turn's `after`).
    fn wait_for_sync(&mut self, live: &Live, after: u64) -> u64 {
        self.wait_for_sync_within(live, after, LIVE_SYNC_LIMIT)
    }

    /// [`Chat::wait_for_sync`] bounded by `limit` (offline: a bound already
    /// passed fails at the first read).
    fn wait_for_sync_within(&mut self, live: &Live, after: u64, limit: Duration) -> u64 {
        let test = self.test;
        let session = self.session.clone().unwrap_or_else(|| panic!("{test}: no session id after the turn"));
        let path = live.paths.transcript_manifest(&session);
        let t = Instant::now();
        loop {
            let missing = match std::fs::read_to_string(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => format!("no manifest of {session} ({})", path.display()),
                Err(e) => format!("the manifest of {session}: {}: {e}", path.display()),
                Ok(text) => match toml::from_str::<toml::Table>(&text) {
                    Err(e) => format!("the manifest of {session}: {}: {}", path.display(), no_account(&e.to_string())),
                    Ok(m) => {
                        let committed = m.get("committed").and_then(toml::Value::as_integer).and_then(|n| u64::try_from(n).ok()).unwrap_or(0);
                        if vm_part_past(&m, &session, after) {
                            eprintln!("{test}: the turn's sync committed {committed} bytes of {session} {} ms after its result (before it: {after})", t.elapsed().as_millis());
                            return committed;
                        }
                        format!("no part of the VM's with a version past {after} bytes in the manifest of {session} ({committed} bytes committed; its parts: {:?})", manifest_parts(&m))
                    }
                },
            };
            assert!(t.elapsed() < limit, "{test}: {missing}, {limit:?} after the turn's result with the chat open: the turn's sync did not commit");
            let until = Instant::now() + LIVE_SYNC_POLL;
            while self.next(until).is_some() {}
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("{test}: the wrapper exited ({status}) while the test waited for the turn's sync ({missing}); its stderr: {}", self.stderr_now());
            }
            // At the wrapper's EOF `next` returns at once: the rest of the interval is slept.
            std::thread::sleep(until.saturating_duration_since(Instant::now()));
        }
    }
}

/// Offline: [`Chat::wait_for_sync`] over a chat whose wrapper is `cat` (it
/// stays open and says only what it is sent) and manifests the product's
/// own writer (`s3::manifest::write`) puts down meanwhile. No manifest, or
/// one whose only parts past `after` are the Mac's or have no version, is
/// what the bound names; once a part of the VM's with its version ends
/// past `after` (a segment, the next one at the committed length, then a
/// new generation's base) the wait returns the committed length, the
/// chat's lines read meanwhile; the wrapper's exit fails it at once.
#[test]
fn wait_for_sync_takes_only_a_part_of_the_vm_past_what_was_committed() {
    use ai_env_cli::bridge::s3::manifest::{self, Manifest, ManifestPart};
    use ai_env_cli::wire::s3::S3Key;
    const TEST: &str = "wait_for_sync_takes_only_a_part_of_the_vm_past_what_was_committed";
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
    let live = Live { _dir: dir, paths, cfg: BridgeConfig::default(), creds: test_creds() };
    let sid = uuid::Uuid::now_v7().to_string();
    let target = ai_env_cli::bridge::s3::S3Target { bucket: "ai-env-transcripts-123456789012".into(), owner: "123456789012".into(), endpoint: ai_env_cli::bridge::s3::S3Endpoint::Aws };
    let part = |key: S3Key, version: &str, from: u64, len: u64| ManifestPart { key: key.render(), version_id: version.into(), from, len, sha256: "0".repeat(64), encoding: None, stored_len: None, stored_sha256: None };
    let (fp, at) = ("0".repeat(64), "2026-10-19T00:00:00.000Z");
    // A chat begun on the Mac (its object: 0..100), then a segment of the VM's whose version S3 did not name.
    let mut m = Manifest::new(&sid, &target, manifest::ORIGIN_MAC, &format!("-w/{sid}.jsonl"), at);
    m.parts.push(part(S3Key::Mac { session: sid.clone(), sha256: "a".repeat(64) }, "m1", 0, 100));
    m.committed = 100;
    m.commit_segment(part(S3Key::Segment { session: sid.clone(), gen: 1, offset: 100 }, "", 100, 50), &fp, None, "microvm-1", at);
    // The wrapper: `cat`, its lines read as `Chat::open` reads ai-env-claude's.
    let child = std::process::Command::new("/bin/cat").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("cat runs");
    let mut chat = Chat::over(TEST, child);
    chat.session = Some(sid.clone());
    // A wait whose bound has passed: what it names.
    let fails = |chat: &mut Chat, after: u64| {
        let e = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| chat.wait_for_sync_within(&live, after, Duration::ZERO))).expect_err("a bound already passed fails the wait");
        e.downcast_ref::<String>().cloned().unwrap_or_default()
    };
    let said = fails(&mut chat, 0);
    assert!(said.contains(&format!("no manifest of {sid}")), "{said}");
    manifest::write(&live.paths, &m).unwrap();
    let said = fails(&mut chat, 0);
    assert!(said.contains("no part of the VM's with a version past 0 bytes") && said.contains("150 bytes committed"), "{said}");
    // The segment's version lands while the chat says a line.
    let later = |m: Manifest| {
        let paths = live.paths.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            manifest::write(&paths, &m).unwrap();
        })
    };
    m.parts[1].version_id = "v2".into();
    let t = Instant::now();
    let writer = later(m.clone());
    chat.send(&serde_json::json!({"type": "system", "subtype": "status", "said": "meanwhile"}));
    assert_eq!(chat.wait_for_sync(&live, 0), 150);
    assert!(t.elapsed() >= Duration::from_millis(600), "{:?}", t.elapsed());
    writer.join().unwrap();
    assert!(String::from_utf8_lossy(&chat.stdout).contains("\"said\":\"meanwhile\""), "the chat's line was read meanwhile");
    // Past 150 only a newer part counts: here the next segment, at 150 and shorter than it (its end counts, not its length).
    let said = fails(&mut chat, 150);
    assert!(said.contains("past 150 bytes"), "{said}");
    m.commit_segment(part(S3Key::Segment { session: sid.clone(), gen: 1, offset: 150 }, "v3", 150, 25), &fp, None, "microvm-1", at);
    let writer = later(m.clone());
    assert_eq!(chat.wait_for_sync(&live, 150), 175);
    writer.join().unwrap();
    // Past 175: a new generation's base, from 0.
    let said = fails(&mut chat, 175);
    assert!(said.contains("past 175 bytes"), "{said}");
    m.commit_base(2, part(S3Key::Base { session: sid.clone(), gen: 2 }, "v4", 0, 200), &fp, None, "microvm-1", at);
    let writer = later(m.clone());
    assert_eq!(chat.wait_for_sync(&live, 175), 200);
    writer.join().unwrap();
    // The wrapper ends (its stdin closed): the wait fails at once, not at its bound.
    chat.stdin = None;
    let t = Instant::now();
    let e = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| chat.wait_for_sync(&live, 200))).expect_err("the wrapper's exit fails the wait");
    let said = e.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(said.contains("the wrapper exited") && t.elapsed() < Duration::from_secs(5), "{said} ({:?})", t.elapsed());
}

/// A request of the Mac to the transcripts bucket with its own runtime key
/// (outside the gateway endpoint): `method` on `key` (`version` when
/// given), `headers` signed besides the owner's: S3's status and `<Code>`.
async fn mac_s3(api: &SdkMicrovmApi, target: &ai_env_cli::bridge::s3::S3Target, method: ai_env_cli::bridge::s3::S3Method, key: &str, version: Option<&str>, headers: Vec<(String, String)>, body: Vec<u8>) -> (u16, Option<String>) {
    use ai_env_cli::bridge::s3::{presign, S3Method, S3Sign};
    let query = version.map(|v| vec![("versionId".to_string(), v.to_string())]).unwrap_or_default();
    let req = presign::request(method, target, Some(key.to_string()), query, headers, ai_env_cli::wire::s3::PRESIGN_EXPIRY);
    let url = api.presign(&req).await.unwrap_or_else(|e| panic!("presign: {}", no_account(&e.to_string())));
    let verb = if method == S3Method::Put { reqwest::Method::PUT } else { reqwest::Method::GET };
    let mut rb = tls::reqwest_client().unwrap().request(verb, url.expose());
    for (name, value) in &req.headers {
        rb = rb.header(name.as_str(), value.as_str());
    }
    // Never reqwest's Display or Debug of a send failure: either holds the presigned URL (its signature, the
    // runtime key's id, the bucket), which `--nocapture` would print. The URL goes at its source, the rest is scrubbed.
    let resp = rb.body(body).send().await.unwrap_or_else(|e| panic!("the request to S3: {}", no_account(&scrub(&e.without_url().to_string()))));
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, ai_env_cli::bridge::s3::client::error_code(&text))
}

/// The bucket of the test's root (`state/infra.toml`'s, copied).
fn s3_target(live: &Live) -> ai_env_cli::bridge::s3::S3Target {
    ai_env_cli::bridge::s3::S3Target::resolve(&live.paths, &VmKnobs::default()).unwrap_or_else(|e| panic!("the transcripts bucket: {e} (run make infra-status WRITE=1 after the S9 deploy)"))
}

/// The S3 transcripts of a test's chats, purged when the test ends, passed or
/// failed: one `session forget <sid>... --purge` in the test's root for every
/// session it keeps transcript state of ([`purged_sessions`]), one Touch ID
/// for them all (S10 F1: one unseal), none when there is none. That deletes
/// the objects under `v1/<sid>/`, which only the temporary root's manifests
/// name (no later `session gc --remote` would find them), and the views.
/// Made before [`SessionVms`]: it runs once the chats closed and their VMs
/// ended, so a tail a VM's `/terminate` pushed is purged with the rest.
/// Interrupted, or when the purge fails, the prefixes to delete by hand are
/// printed.
struct PurgeTranscripts<'a>(&'a Live);

/// The sessions [`PurgeTranscripts`] purges, sorted, each once: those the
/// root keeps transcript state of (`state/transcripts/<sid>/`), and those
/// whose row keeps the transcript in S3 (a chat whose sync never committed:
/// no manifest, and S3 may hold its tail).
fn purged_sessions(paths: &Paths) -> Vec<String> {
    let mut sessions: Vec<String> = std::fs::read_dir(paths.transcripts()).map(|dir| dir.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|n| ai_env_cli::bridge::registry::is_uuid(n)).collect()).unwrap_or_default();
    // A chat whose sync never committed has no directory there; its row names S3, a trace `forget --purge` takes.
    sessions.extend(ai_env_cli::bridge::registry::list(paths).unwrap_or_default().into_iter().filter(|r| r.transcript_home.is_some()).map(|r| r.session_id));
    sessions.sort();
    sessions.dedup();
    sessions
}

/// The one command that purges `sessions` (S10 F1): `session forget <sid>... --purge`; none for none.
fn purge_args(sessions: &[String]) -> Option<Vec<String>> {
    (!sessions.is_empty()).then(|| ["session", "forget"].iter().map(|w| (*w).to_string()).chain(sessions.iter().cloned()).chain(std::iter::once("--purge".to_string())).collect())
}

impl Drop for PurgeTranscripts<'_> {
    fn drop(&mut self) {
        let live = self.0;
        let sessions = purged_sessions(&live.paths);
        let Some(args) = purge_args(&sessions) else { return };
        let by_hand = format!("the objects under v1/<sid>/ in the transcripts bucket are left for each of {}: delete them by hand", sessions.join(", "));
        let said = if CRED_SIGNAL.load(Ordering::SeqCst) != 0 {
            format!("guard: interrupted, session forget --purge not run: {by_hand}")
        } else {
            announce_touch_id("guard", &format!("session forget --purge of {} session(s): their S3 objects", sessions.len()));
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            // A panic of the command's runner (stopped past its limit) is caught: a drop never panics.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ai_env_live(live, &args))) {
                Ok(out) if out.status.success() => format!("guard: purged the transcripts of {}", sessions.join(", ")),
                Ok(out) => format!("guard: session forget --purge exited {:?}: {by_hand}", out.status.code()),
                Err(_) => format!("guard: session forget --purge did not finish: {by_hand}"),
            }
        };
        let _ = writeln!(std::io::stderr(), "{said}");
    }
}

/// A remote chat's view on the Mac, as its session row names it: its lines,
/// after asserting the file is a view (`wire::view::is_view_head`) holding at
/// most `[transcript].view_messages` messages.
fn assert_a_view(test: &str, live: &Live, session: &str) -> Vec<String> {
    let row = ai_env_cli::bridge::registry::read(&live.paths, session).unwrap().unwrap_or_else(|| panic!("{test}: no session row of {session}"));
    assert_eq!((row.transcript_home.as_deref(), row.origin.as_deref()), (Some("s3"), Some("vm")), "{test}: the session's transcript is kept in S3, begun in the VM");
    let view = mac_projects().join(row.view.as_deref().unwrap_or_else(|| panic!("{test}: the row names no view")));
    let bytes = std::fs::read(&view).unwrap_or_else(|e| panic!("{test}: {}: {e}", view.display()));
    assert!(ai_env_cli::wire::view::is_view_head(&bytes[..bytes.len().min(ai_env_cli::wire::view::VIEW_HEAD_READ)]), "{test}: {} is no view", view.display());
    let lines: Vec<String> = String::from_utf8_lossy(&bytes).lines().map(str::to_string).collect();
    let messages = lines.iter().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|v| v["type"] == "user" || v["type"] == "assistant").count();
    assert!(messages >= 1 && messages <= live.cfg.transcript.view_messages as usize, "{test}: the view holds {messages} messages (at most {})", live.cfg.transcript.view_messages);
    lines
}

/// T9 S3 live (B6): a chat's turns land in S3, not on the Mac. Two turns of
/// a chat in remote mode, the chat left open after each until that turn's
/// own sync committed it ([`Chat::wait_for_sync`]; the first wait also
/// keeps the first turn's sync from passing for the second's), then the
/// close, and then: the session row keeps its transcript in S3
/// (`transcript_home`, `origin` vm); the Mac's manifest lists parts of the
/// VM's (`v1/<sid>/vm/…`, each with its version), and S3 lists them; the
/// Mac's file is the view (its mark first, at most the configured messages);
/// each push was audited (S3 answered 200) and the view written; and a GET
/// of a part by the Mac is refused (403). The chat's objects are purged at
/// the end ([`PurgeTranscripts`]). Three Touch IDs: the chat's, the test
/// process's runtime key, the purge.
#[test]
#[ignore = "live, S9's S3 store, starts a MicroVM and asks the model (three Touch IDs): AI_ENV_AWS_TESTS=1 make test-aws S3=1"]
fn live_s3_turn_lands_in_s3_not_on_mac() {
    const TEST: &str = "live_s3_turn_lands_in_s3_not_on_mac";
    if !s3_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[("suspend_on_close", toml::Value::Boolean(false))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s3-turn");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    // What the manifest committed before each turn: 0 before the first.
    let mut committed = 0;
    for n in 1..=2 {
        let turn = chat.turn(&format!("Reply with exactly OK {n}"));
        assert_eq!(turn.result["is_error"], false, "{TEST}: turn {n}: {}", turn.result);
        committed = chat.wait_for_sync(&live, committed);
    }
    let (code, close) = chat.close();
    assert_closed_well(TEST, &live, &chat, code, close);
    let session = chat.session.clone().expect("the chat's session id");
    let lines = assert_a_view(TEST, &live, &session);
    let manifest = s3_manifest(TEST, &live, &session);
    let parts = manifest_parts(&manifest);
    let prefix = format!("v1/{session}/vm/");
    assert!(!parts.is_empty() && parts.iter().all(|(k, v)| k.starts_with(&prefix) && v.is_some()), "{TEST}: the manifest's parts: {parts:?}");
    let pushes = live_audit(&live, "transcript_push");
    assert!(!pushes.is_empty() && pushes.iter().all(|r| r["detail"]["s3_status"] == "200"), "{TEST}: the pushes: {pushes:?}");
    assert!(live_audit(&live, "transcript_view").iter().any(|r| r["detail"]["outcome"] == "written"), "{TEST}: the view was written");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (listed, refused) = rt.block_on(async {
        use ai_env_cli::bridge::s3::{client::S3Client, S3Method};
        let api = connect(&live.creds).await;
        let target = s3_target(&live);
        let listed: Vec<String> = S3Client::new(&api, &target).unwrap().list(&format!("v1/{session}/")).await.unwrap_or_else(|e| panic!("{TEST}: list: {}", no_account(&e.to_string()))).into_iter().map(|l| l.key).collect();
        let (key, version) = &parts[0];
        (listed, mac_s3(&api, &target, S3Method::Get, key, version.as_deref(), Vec::new(), Vec::new()).await)
    });
    for (key, _) in &parts {
        assert!(listed.contains(key), "{TEST}: S3 lists {key}: {listed:?}");
    }
    eprintln!("{TEST}: {} parts in S3, the view {} lines; the Mac's GET of a part: {refused:?}", parts.len(), lines.len());
    assert_eq!(refused, (403, Some("AccessDenied".to_string())), "{TEST}: the Mac cannot read the VM's transcript");
    let out = chat.output();
    sweep_live(&live, &[&out], &[]);
}

/// T9 S3 live (B6): a reopen in a new VM restores the chat from S3. A word
/// told in a chat is recalled after its VM was terminated (`vm terminate`
/// syncs first): the reopened chat (`--resume`) starts a new VM, the
/// transcript is pulled from S3 into it before the spawn
/// (`transcript:restored`, a `transcript_pull` audit row `written`), the
/// conversation goes on, and the Mac still holds only the view. The chat's
/// objects are purged at the end ([`PurgeTranscripts`]). Four Touch IDs:
/// two chats, the terminate and the purge.
#[test]
#[ignore = "live, S9's S3 store, starts two MicroVMs and asks the model (four Touch IDs): AI_ENV_AWS_TESTS=1 make test-aws S3=1"]
fn live_s3_reopen_new_vm_restores() {
    const TEST: &str = "live_s3_reopen_new_vm_restores";
    if !s3_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[("suspend_on_close", toml::Value::Boolean(false))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s3-reopen");
    let word = format!("harbour{}", uuid::Uuid::now_v7().simple().to_string().chars().rev().take(4).collect::<String>());
    let mut first = Chat::open(TEST, &live, &ws, &[]);
    first.initialize();
    first.turn(&format!("Remember this word for later: {word}. Reply with exactly OK"));
    let (code, close) = first.close();
    let row = assert_closed_well(TEST, &live, &first, code, close);
    let (vm1, session) = (note_part(&row, "vm").expect("the first VM"), first.session.clone().expect("the chat's session id"));
    let terminate = ai_env_live(&live, &["vm", "terminate", &vm1, "--yes"]);
    assert_eq!(terminate.status.code(), Some(0), "{TEST}: vm terminate");
    let resume = format!("--resume={session}");
    let mut second = Chat::open(TEST, &live, &ws, &[&resume]);
    second.initialize();
    let turn = second.turn("Which word did I ask you to remember? Reply with the word only.");
    let (code, close) = second.close();
    let row = assert_closed_well(TEST, &live, &second, code, close);
    let answer = turn.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer {answer:?} lacks the word");
    let vm2 = note_part(&row, "vm").expect("the second VM");
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    assert_eq!((note_part(&row, "vm_how").as_deref(), note_part(&row, "transcript").as_deref()), (Some("started"), Some("restored")), "{TEST}");
    let pulls = live_audit(&live, "transcript_pull");
    assert!(pulls.iter().any(|r| r["detail"]["vm"] == vm2.as_str() && r["detail"]["outcome"] == "written"), "{TEST}: the restore is audited: {pulls:?}");
    assert!(live_audit(&live, "transcript_put").is_empty(), "{TEST}: nothing went up from the Mac");
    assert_a_view(TEST, &live, &session);
    let (a, b) = (first.output(), second.output());
    sweep_live(&live, &[&a, &b, &terminate], &[]);
}

/// The audit row of `event` whose detail's `session` is `session`, the newest: (bytes, ms) as numbers.
fn timed_row(test: &str, live: &Live, event: &str, session: &str) -> (u64, u64) {
    timed_row_of(test, live, event, session, None)
}

/// [`timed_row`] of the newest row whose `kind` is `kind`, when one is given (S10: the sync's base push, beside
/// the subtree's files).
fn timed_row_of(test: &str, live: &Live, event: &str, session: &str, kind: Option<&str>) -> (u64, u64) {
    let rows = live_audit(live, event);
    let row = rows.iter().rev().find(|r| r["detail"]["session"] == session && kind.is_none_or(|k| r["detail"]["kind"] == k)).unwrap_or_else(|| panic!("{test}: no {event} row of {session}: {rows:?}"));
    let num = |k: &str| row["detail"][k].as_str().and_then(|v| v.parse().ok()).or_else(|| row["detail"][k].as_u64()).unwrap_or_else(|| panic!("{test}: {event}'s {k}: {row}"));
    let bytes = if row["detail"].get("bytes").is_some() { num("bytes") } else { num("len") };
    (bytes, num("ms"))
}

/// MB/s of `bytes` in `ms`.
fn rate(bytes: u64, ms: u64) -> f64 {
    bytes as f64 / 1_000_000.0 / (ms.max(1) as f64 / 1000.0)
}

/// C §C.3.10: the words of the gib test's filler. Twenty, drawn uniformly, so that `/usr/bin/gzip -n -6` compresses
/// the filler about 4x (4.0x measured at the builder: 32 words gave 3.8x, 100 gave 3.6x); the fox sentence S10
/// repeated compressed over 100x and proved nothing.
const FILLER_WORDS: [&str; 20] = ["the", "of", "and", "to", "in", "is", "was", "for", "on", "that", "with", "as", "by", "at", "from", "it", "his", "an", "were", "are"];

/// A line's filler in the gib test's chat (C.3.10): 64 KiB.
const FILLER_LINE: usize = 64 * 1024;

/// splitmix64's next output, `state` advanced.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// C.3.10: `bytes` of plain words seeded by `seed` (a line's number): [`FILLER_WORDS`] drawn by [`splitmix64`],
/// spaces between, a period after every 12th word, cut at `bytes` (ASCII).
fn filler(seed: u64, bytes: usize) -> String {
    let mut state = seed;
    let mut out = String::with_capacity(bytes + 16);
    let mut words = 0u64;
    while out.len() < bytes {
        let n = u64::try_from(FILLER_WORDS.len()).expect("a count");
        let word = FILLER_WORDS[usize::try_from(splitmix64(&mut state) % n).expect("an index")];
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
        words += 1;
        if words.is_multiple_of(12) {
            out.push('.');
        }
    }
    out.truncate(bytes);
    out
}

/// C.3.10, offline: 4 MiB of the gib test's filler (lines of [`FILLER_LINE`], seeded by their numbers) through
/// `/usr/bin/gzip -n -6 -c` compress 3.0x to 6.0x (about 4x), the ratio printed; the filler is seeded (the same
/// seed, the same text) and plain words.
#[test]
fn the_gib_filler_compresses_about_four_times() {
    use std::io::Write as _;
    let mut text = String::with_capacity(4 << 20);
    let mut line = 0u64;
    while text.len() < 4 << 20 {
        text.push_str(&filler(line, FILLER_LINE));
        line += 1;
    }
    text.truncate(4 << 20);
    assert_eq!(filler(7, 1000), filler(7, 1000), "seeded");
    assert_ne!(filler(7, 1000), filler(8, 1000));
    assert!(filler(1, 1000).len() == 1000 && filler(1, 1000).bytes().all(|b| b.is_ascii_lowercase() || b == b' ' || b == b'.'), "plain words");
    let mut gzip = std::process::Command::new("/usr/bin/gzip").args(["-n", "-6", "-c"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().expect("/usr/bin/gzip");
    let mut stdin = gzip.stdin.take().expect("gzip's stdin");
    let feed = std::thread::spawn(move || stdin.write_all(text.as_bytes()).map(|()| text.len()));
    let out = gzip.wait_with_output().expect("gzip's output");
    let fed = feed.join().expect("the feed").expect("written");
    assert!(out.status.success() && !out.stdout.is_empty(), "gzip: {:?}", out.status);
    let ratio = fed as f64 / out.stdout.len() as f64;
    eprintln!("the gib filler: {fed} bytes, gzip -n -6 {} bytes: {ratio:.2}x", out.stdout.len());
    assert!((3.0..=6.0).contains(&ratio), "about 4x: {ratio:.2}x");
}

/// The synthetic chat's shape for [`live_s3_gib_round_trip_timing`] (S10
/// F12): its main transcript's MiB, and its subtree's MiB in `files`
/// subagent files. AI_ENV_S3_CHAT gives it as
/// `main=<MiB>,subtree=<MiB>,files=<n>` (`make test-aws S3=1 CHAT=dev`: the
/// development chat's, from its file names and sizes alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChatShape {
    main_mib: u64,
    subtree_mib: u64,
    files: u64,
}

impl ChatShape {
    /// S9's gib: 1024 MiB of transcript, no subtree.
    const GIB: ChatShape = ChatShape { main_mib: 1024, subtree_mib: 0, files: 0 };

    /// AI_ENV_S3_CHAT's value: unset, [`ChatShape::GIB`]; else exactly
    /// `main=<MiB>,subtree=<MiB>,files=<n>` in that order, decimal, a main of
    /// 1 MiB or more, a subtree with files and files with a subtree, the whole
    /// at most what `session stage` takes (`STAGE_MAX`), and (S11, C.3.5) the
    /// main and each subtree file at most what one file may be
    /// (`STAGE_FILE_MAX`: the last subtree file, which takes the remainder, is
    /// the largest). Anything else is refused naming the form it should have.
    fn parse(value: Option<&str>) -> Result<ChatShape, String> {
        let Some(text) = value else { return Ok(ChatShape::GIB) };
        let bad = || format!("AI_ENV_S3_CHAT={text:?} is not main=<MiB>,subtree=<MiB>,files=<n> (make test-aws S3=1 CHAT=dev sets it from S3_CHAT_DEV)");
        let mut nums = [0u64; 3];
        let mut parts = text.split(',');
        for (slot, key) in nums.iter_mut().zip(["main", "subtree", "files"]) {
            let digits = parts.next().and_then(|p| p.strip_prefix(key)).and_then(|p| p.strip_prefix('=')).filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())).ok_or_else(bad)?;
            *slot = digits.parse().map_err(|_| bad())?;
        }
        if parts.next().is_some() {
            return Err(bad());
        }
        let [main_mib, subtree_mib, files] = nums;
        let max_mib = ai_env_cli::bridge::s3::stage::STAGE_MAX >> 20;
        let file_max = ai_env_cli::bridge::s3::stage::STAGE_FILE_MAX;
        let shaped = main_mib > 0 && (subtree_mib == 0) == (files == 0) && main_mib.saturating_add(subtree_mib) <= max_mib;
        // Within the whole's cap the bytes cannot overflow; the last subtree file takes the remainder.
        let largest_file = |total: u64| total.checked_div(files).map_or(0, |each| each + total % files);
        if !shaped || main_mib << 20 > file_max || largest_file(subtree_mib << 20) > file_max {
            return Err(format!("{}: a main of 1 MiB or more, a subtree with files (and files with a subtree), each file {} MiB at most and {max_mib} MiB at most in all", bad(), file_max >> 20));
        }
        Ok(ChatShape { main_mib, subtree_mib, files })
    }

    /// The main transcript's bytes (written to just past them).
    fn main_bytes(self) -> u64 {
        self.main_mib << 20
    }

    /// Each subtree file's bytes: the subtree's split evenly, the remainder in the last.
    fn file_sizes(self) -> Vec<u64> {
        let total = self.subtree_mib << 20;
        (0..self.files).map(|k| total / self.files + if k + 1 == self.files { total % self.files } else { 0 }).collect()
    }
}

/// Offline (S10 F12): AI_ENV_S3_CHAT's shapes. Unset is S9's gib; the
/// development chat's form parses, its subtree split over its files to the
/// byte; every other form is refused naming the one it should have.
#[test]
fn chat_shape_reads_main_subtree_files_or_defaults_to_s9s_gib() {
    assert_eq!(ChatShape::parse(None), Ok(ChatShape::GIB));
    assert_eq!((ChatShape::GIB.main_bytes(), ChatShape::GIB.file_sizes()), (1 << 30, Vec::new()), "S9's 1 GiB, no subtree");
    let dev = ChatShape::parse(Some("main=215,subtree=1650,files=40")).unwrap();
    assert_eq!(dev, ChatShape { main_mib: 215, subtree_mib: 1650, files: 40 });
    assert_eq!(dev.main_bytes(), 215 << 20);
    let sizes = dev.file_sizes();
    assert_eq!((sizes.len(), sizes.iter().sum::<u64>()), (40, 1650 << 20));
    assert_eq!(ChatShape::parse(Some("main=1,subtree=1,files=3")).unwrap().file_sizes(), [349_525, 349_525, 349_526], "the remainder in the last");
    assert_eq!(ChatShape::parse(Some("main=1024,subtree=0,files=0")), Ok(ChatShape::GIB));
    // S11 (C.3.5): each file 4 GiB at most, 16 GiB at most in all; both caps exactly parse.
    let edge = ChatShape::parse(Some("main=4096,subtree=12288,files=4")).unwrap();
    assert_eq!((edge.main_bytes(), edge.file_sizes()), (4096 << 20, vec![3072 << 20; 4]));
    for capped in ["main=4097,subtree=0,files=0", "main=4096,subtree=12289,files=4", "main=1,subtree=4097,files=1"] {
        let e = ChatShape::parse(Some(capped)).expect_err(capped);
        assert!(e.ends_with("a main of 1 MiB or more, a subtree with files (and files with a subtree), each file 4096 MiB at most and 16384 MiB at most in all"), "{capped}: {e}");
    }
    for bad in [
        "",
        "main=215",
        "main=215,subtree=1650",
        "main=215,subtree=1650,files=40,x=1",
        "subtree=1650,main=215,files=40",
        "main=215,subtree=1.6G,files=40",
        "main=,subtree=0,files=0",
        "main=+5,subtree=0,files=0",
        " main=215,subtree=0,files=0",
        "main=0,subtree=0,files=0",
        "main=215,subtree=0,files=4",
        "main=215,subtree=10,files=0",
        "main=4097,subtree=0,files=0",
        "main=4096,subtree=12289,files=4",
        "main=1,subtree=4097,files=1",
        "main=99999999999999999999,subtree=0,files=0",
    ] {
        let e = ChatShape::parse(Some(bad)).expect_err(bad);
        assert!(e.contains("is not main=<MiB>,subtree=<MiB>,files=<n>"), "{bad}: {e}");
    }
}

/// T9 S3 live (B6): a 1 GiB chat begun on the Mac round-trips through S3,
/// and claude's memory with it open is read. S10 (F12): AI_ENV_S3_CHAT gives
/// the chat another shape, `main=<MiB>,subtree=<MiB>,files=<n>` ([`ChatShape`],
/// `make test-aws S3=1 CHAT=dev`: the development chat's, from its names and
/// sizes alone): the main transcript that large, and `files` subagent files
/// of the subtree's MiB in all under `<sid>/subagents/`; unset, S9's gib (1024
/// MiB, no subtree). A subtree goes up with the stage, the reopen keeps the
/// main transcript (`transcript:kept`) and pulls only the subtree's files
/// after its spawn (`restore_subtree`, one `transcript_pull` row each, its
/// `too_large` path past 256 MiB). A synthetic transcript (never
/// the development chat: JSONL of plain prompts and replies, written here
/// under the fixture's project directory and removed on every path) ends
/// with a compaction as 2.1.302 writes one and a short exchange after it:
/// a turn's context is the summary and that exchange, never the 1 GiB
/// before it, and the view the stage leaves is that exchange. A reopen
/// pulls at most 64 MiB inline, so the chat is staged with `--warm`
/// (`session stage --warm`: scanned, a multipart upload from the Mac, the
/// view left in its place; then the workspace's VM warmed and the chat
/// restored from S3 into it with no deadline, a `transcript_pull` row
/// `written` for that VM). The chat reopens remote on that VM
/// (`vm_how:reused`) and keeps the copy it holds (`transcript:kept`:
/// nothing is pulled at the reopen); one turn (claude may parse the whole
/// file first) makes the session's row, which `session sync` needs; with
/// the chat still open, `vm exec` prints the VM's MemTotal and
/// MemAvailable and the VmHWM and VmRSS of each claude process (printed,
/// never judged). After the close the VM's copy is rewritten in place (a
/// new inode) and `session sync` pushes it whole as a new generation's
/// base. Each transfer's rate is printed (MB/s, from the audit) with the
/// reopen's `initialize` time and the memory facts, and the chat's objects
/// are purged at the end ([`PurgeTranscripts`]). The stage starts the
/// warmed VM, not the chat: its row is in the test's root, so
/// [`SessionVms`] ends it on every path. Eight Touch IDs: the test
/// process's own, two for the stage and its warm (the runtime key, then
/// the key and the setup-token together from a current combined.env; the
/// restore adds none), the chat, two `vm exec`, the sync, the purge. About
/// half an hour: at the 4 MB/s baselines the VM's pull and its full upload
/// take about 4.5 minutes each, the stage what the Mac's uplink allows;
/// each transfer may take 30 minutes (the stage command holds two, and the
/// warm), the reopen's `initialize` and the turn 10 each. The warmed VM's
/// wall (`max_duration_s`) is the sum of every bound from the stage to the
/// sync, about two hours ([`wrapper_world`]'s 900 s would end it inside
/// them), and `reuse_per_workspace` is set on: the reopen takes the warmed
/// VM only through SELECT_VM's reuse.
#[test]
#[ignore = "live, S9's S3 store, a 1 GiB chat (or AI_ENV_S3_CHAT's shape: make test-aws S3=1 CHAT=dev) round trip through a warmed MicroVM and claude's memory with it open (about half an hour; eight Touch IDs): AI_ENV_AWS_TESTS=1 make test-aws S3=1"]
fn live_s3_gib_round_trip_timing() {
    const TEST: &str = "live_s3_gib_round_trip_timing";
    const TRANSFER_LIMIT: Duration = Duration::from_secs(1800);
    // The reopen's initialize and its first turn: claude may parse the whole file before it answers either.
    const TURN_LIMIT: Duration = Duration::from_secs(600);
    if !s3_live() {
        return;
    }
    let shape = ChatShape::parse(std::env::var("AI_ENV_S3_CHAT").ok().as_deref()).unwrap_or_else(|e| panic!("{TEST}: {e}"));
    let (main, subtree) = (shape.main_bytes(), shape.file_sizes().iter().sum::<u64>());
    eprintln!("{TEST}: the chat's shape: {shape:?} ({main} bytes of transcript, {subtree} of subtree)");
    let _signals = Interrupts::catch();
    // The stage command's two transfers and the warm between them; then the warmed VM's wall, which starts after
    // the upload: past every bound from the stage to the sync (the reopen, the turn, two `vm exec`, the close).
    let stage_limit = TRANSFER_LIMIT * 2 + LIVE_INIT_LIMIT;
    let wall = stage_limit + TURN_LIMIT * 2 + CRED_COMMAND_LIMIT * 2 + LIVE_EXIT_LIMIT + TRANSFER_LIMIT;
    let live = wrapper_world(&[
        ("suspend_on_close", toml::Value::Boolean(false)),
        ("max_duration_s", toml::Value::Integer(i64::try_from(wall.as_secs()).unwrap())),
        ("reuse_per_workspace", toml::Value::Boolean(true)),
    ]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s3-gib");
    let slug = ai_env_cli::wire::slug::project_dir_name(&ws).expect("the fixture's project directory name");
    let dir = mac_projects().join(&slug);
    let _gone = RemoveOnDrop(dir.clone());
    std::fs::create_dir_all(&dir).unwrap();
    let session = uuid::Uuid::now_v7().to_string();
    // The synthetic chat, as the view fixture's tails are written (tests/fixtures/view/tails/branched.jsonl): one
    // chain of prompts and replies of 64 KiB of plain words each to just past the shape's main, ending on a reply (a reply's
    // content an array of one text block); then a compaction (the boundary, with no parent, its logical parent the
    // chain's last reply; the summary, in no view) and one short exchange after it, the newest leaf. Its times are
    // the hour before now, the compaction half an hour after the chain: the chat's own turn comes after them all.
    {
        use std::io::Write as _;
        let mut w = std::io::BufWriter::new(std::fs::File::create(dir.join(format!("{session}.jsonl"))).unwrap());
        let (cwd, start) = (ws.display().to_string(), ai_env_cli::wire::time::unix_now_ms() - 3_600_000);
        let at = |ms: u64| ai_env_cli::wire::time::rfc3339_utc_ms(start + ms);
        let entry = |kind: &str, uuid: &str, parent: serde_json::Value, ms: u64, content: serde_json::Value| {
            serde_json::json!({"parentUuid": parent, "isSidechain": false, "userType": "external", "cwd": cwd, "sessionId": session, "version": "2.1.302", "gitBranch": "main", "type": kind, "message": {"role": kind, "content": content}, "uuid": uuid, "timestamp": at(ms)})
        };
        let mut put = |line: &serde_json::Value| {
            let text = format!("{line}\n");
            w.write_all(text.as_bytes()).unwrap();
            text.len() as u64
        };
        let (mut written, mut parent, mut n) = (0u64, serde_json::Value::Null, 0u64);
        while written < main || n % 2 == 1 {
            let uuid = uuid::Uuid::now_v7().to_string();
            let text = filler(n, FILLER_LINE);
            let line = if n % 2 == 0 { entry("user", &uuid, parent, n, serde_json::json!(text)) } else { entry("assistant", &uuid, parent, n, serde_json::json!([{"type": "text", "text": text}])) };
            written += put(&line);
            parent = serde_json::Value::String(uuid);
            n += 1;
        }
        // The compaction as 2.1.302 writes it; preTokens is the chain's bytes at about four a token.
        let boundary = uuid::Uuid::now_v7().to_string();
        put(&serde_json::json!({
            "parentUuid": null, "logicalParentUuid": parent, "isSidechain": false, "userType": "external", "cwd": cwd, "sessionId": session, "version": "2.1.302", "gitBranch": "main",
            "type": "system", "subtype": "compact_boundary", "content": "Conversation compacted", "isMeta": false, "uuid": boundary, "timestamp": at(1_800_000),
            "compactMetadata": {"trigger": "manual", "preTokens": written / 4},
        }));
        let summary = uuid::Uuid::now_v7().to_string();
        let mut line = entry("user", &summary, serde_json::json!(boundary), 1_801_000, serde_json::json!("This session is being continued from a previous conversation: a synthetic chat of plain words, nothing to act on."));
        line["isCompactSummary"] = serde_json::Value::Bool(true);
        line["isVisibleInTranscriptOnly"] = serde_json::Value::Bool(true);
        put(&line);
        let prompt = uuid::Uuid::now_v7().to_string();
        put(&entry("user", &prompt, serde_json::json!(summary), 1_860_000, serde_json::json!("A short question after the compaction")));
        put(&entry("assistant", &uuid::Uuid::now_v7().to_string(), serde_json::json!(prompt), 1_865_000, serde_json::json!([{"type": "text", "text": "A short answer after the compaction"}])));
        w.flush().unwrap();
        // The subtree: each file a subagent's sidechain of the same words, prompt and reply in turn, to just past
        // its size (one line at least).
        let agents = dir.join(&session).join("subagents");
        for (k, size) in shape.file_sizes().into_iter().enumerate() {
            std::fs::create_dir_all(&agents).unwrap();
            let mut f = std::io::BufWriter::new(std::fs::File::create(agents.join(format!("agent-{k:04}.jsonl"))).unwrap());
            let agent = format!("{:08x}", k + 1);
            let (mut written, mut parent, mut n) = (0u64, serde_json::Value::Null, 0u64);
            while written < size || n == 0 {
                let uuid = uuid::Uuid::now_v7().to_string();
                let kind = if n % 2 == 0 { "user" } else { "assistant" };
                let mut line = entry(kind, &uuid, parent, 60_000 + n, serde_json::json!([{"type": "text", "text": filler(n, FILLER_LINE)}]));
                line["isSidechain"] = serde_json::Value::Bool(true);
                line["agentId"] = serde_json::Value::String(agent.clone());
                let text = format!("{line}\n");
                f.write_all(text.as_bytes()).unwrap();
                written += text.len() as u64;
                parent = serde_json::Value::String(uuid);
                n += 1;
            }
            f.flush().unwrap();
        }
    }
    // Staged with --warm: the Mac's upload, then the workspace's VM warmed and the chat restored from S3 into it with
    // no deadline (a reopen pulls at most 64 MiB inline; P0 refuses this one when no VM of the workspace lives).
    let t = Instant::now();
    let staged = ai_env_live_within(&live, &["session", "stage", &session, "--warm", "--json"], stage_limit);
    let stage_ms = t.elapsed().as_millis();
    assert_eq!(staged.status.code(), Some(0), "{TEST}: session stage --warm");
    let v: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap_or_else(|e| panic!("{TEST}: session stage --warm --json: {e}"));
    assert_eq!(v["outcome"].as_str(), Some("staged"), "{TEST}: {v}");
    assert!(v["bytes"].as_u64().is_some_and(|b| b >= main + subtree), "{TEST}: the whole chat went up, its subtree too: {v}");
    assert_eq!(v["view"].as_str(), Some(format!("{slug}/{session}.jsonl").as_str()), "{TEST}: the view (the exchange after the compaction) in the chat's place: {v}");
    let (up, up_ms) = timed_row(TEST, &live, "transcript_stage", &session);
    // C.3.10: the chat's gzip ratio, and the stored bytes' rate (the stage row's `stored` and `rate`).
    let stage_rows = live_audit(&live, "transcript_stage");
    let stage_row = stage_rows.iter().rev().find(|r| r["detail"]["session"] == session.as_str()).unwrap_or_else(|| panic!("{TEST}: no transcript_stage row of {session}"));
    let stored = stage_row["detail"]["stored"].as_str().and_then(|n| n.parse::<u64>().ok()).unwrap_or_else(|| panic!("{TEST}: the stage's stored bytes: {stage_row}"));
    eprintln!("{TEST}: the chat's gzip ratio: {up}/{stored} = {:.2}x; the stored bytes went up at {:.1} MB/s (the row's rate: {})", up as f64 / stored.max(1) as f64, rate(stored, up_ms), stage_row["detail"]["rate"]);
    let vm = v["restore"]["vm"].as_str().unwrap_or_else(|| panic!("{TEST}: the warm restored nothing: {v}")).to_string();
    // The pull's own bytes and ms, from its audit row; the command's `restore` says the same bytes (its ms is the whole restore's).
    let (down, down_ms) = timed_row(TEST, &live, "transcript_pull", &session);
    assert_eq!((v["restore"]["outcome"].as_str(), v["restore"]["bytes"].as_u64()), (Some("restored"), Some(down)), "{TEST}: the chat restored into {vm}: {v}");
    assert!(down >= main, "{TEST}: the whole chat came down: {down} bytes");
    let pulled = || live_audit(&live, "transcript_pull").into_iter().filter(|r| r["detail"]["session"] == session.as_str()).collect::<Vec<_>>();
    let pulls = pulled();
    assert!(pulls.iter().any(|r| r["detail"]["vm"] == vm.as_str() && r["detail"]["outcome"] == "written"), "{TEST}: the pull into {vm}: {pulls:?}");
    // The chat reopens remote on the warmed VM, which holds what S3 committed: nothing is pulled.
    let resume = format!("--resume={session}");
    let mut chat = Chat::open(TEST, &live, &ws, &[&resume]);
    let init = chat.initialize_within(TURN_LIMIT);
    // One cheap turn: the pump registers the session's row at a user line (`session sync` refuses a session with
    // no row), and claude has the 1 GiB chat loaded.
    let turn = chat.turn_within("Reply with exactly OK", TURN_LIMIT);
    assert_eq!(chat.session.as_deref(), Some(session.as_str()), "{TEST}: the reopened chat is the staged session");
    let named = ai_env_cli::bridge::registry::read(&live.paths, &session).unwrap().and_then(|r| r.microvm_id);
    assert_eq!(named.as_deref(), Some(vm.as_str()), "{TEST}: the session's row names the warmed VM after the turn");
    // The memory with the chat open: the VM's, then each process whose comm is claude (never its cmdline: the
    // shim, PID 1, carries --claude), in shell builtins alone. Printed, never judged: neither its exit nor a probe
    // stopped past its limit fails the test (an interrupt still ends it).
    let script = "while read -r k v u; do case $k in MemTotal:|MemAvailable:) echo \"$k $v $u\";; esac; done < /proc/meminfo; \
                  for d in /proc/[0-9]*; do read -r c 2>/dev/null < \"$d/comm\" || continue; [ \"$c\" = claude ] || continue; \
                  s=; while read -r k v u; do case $k in VmHWM:|VmRSS:) s=\"$s $k $v $u\";; esac; done 2>/dev/null < \"$d/status\"; echo \"claude (pid ${d#/proc/}):$s\"; done";
    let probe = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ai_env_live(&live, &["vm", "exec", &vm, "--", "sh", "-c", script]))) {
        Ok(out) => Some(out),
        Err(stop) if CRED_SIGNAL.load(Ordering::SeqCst) != 0 => std::panic::resume_unwind(stop),
        Err(_) => None,
    };
    let said = probe.as_ref().map_or_else(|| format!("(stopped past {CRED_COMMAND_LIMIT:?})"), |p| String::from_utf8_lossy(&p.stdout).to_string());
    eprintln!("{TEST}: with the chat open on {vm}, after a turn of {} ms (vm exec exit {:?}):\n{}", turn.ms, probe.as_ref().and_then(|p| p.status.code()), said.trim_end());
    let memory = said.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ");
    assert_eq!(turn.result["is_error"], false, "{TEST}: the turn: {}", turn.result);
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(
        (note_part(&row, "vm").as_deref(), note_part(&row, "vm_how").as_deref(), note_part(&row, "transcript").as_deref()),
        (Some(vm.as_str()), Some("reused"), Some("kept")),
        "{TEST}: the reopen took the warmed VM, running, and kept the chat it holds"
    );
    // No pull of the transcript at the reopen; a subtree's files follow it, one pull each at most.
    let later = pulled().len().saturating_sub(pulls.len());
    eprintln!("{TEST}: {later} pull(s) after the reopen, for the subtree's {} file(s)", shape.files);
    assert!(pulled().starts_with(&pulls) && later as u64 <= shape.files, "{TEST}: no pull of the transcript at the reopen: {:?}", pulled());
    // The VM's copy rewritten in place (a new inode): the sync pushes it whole.
    let file = format!("$HOME/.claude/projects/{slug}/{session}.jsonl");
    let exec = ai_env_live(&live, &["vm", "exec", &vm, "--", "sh", "-c", &format!("cp \"{file}\" \"{file}.copy\" && mv \"{file}.copy\" \"{file}\"")]);
    assert_eq!(exec.status.code(), Some(0), "{TEST}: vm exec");
    let synced = ai_env_live_within(&live, &["session", "sync", &session, "--json"], TRANSFER_LIMIT);
    assert_eq!(synced.status.code(), Some(0), "{TEST}: session sync");
    let v: serde_json::Value = serde_json::from_slice(&synced.stdout).unwrap_or_else(|e| panic!("{TEST}: session sync --json: {e}"));
    assert_eq!((v["outcome"].as_str(), v["pushed"]["kind"].as_str()), (Some("synced"), Some("base")), "{TEST}: a new generation's base: {v}");
    // The newest base push is the sync's: the turn's own step may have pushed a segment before it, and the subtree's
    // files are pushed beside it.
    let (full, full_ms) = timed_row_of(TEST, &live, "transcript_push", &session, Some("base"));
    assert!(full >= main, "{TEST}: the whole copy went up: {full} bytes");
    eprintln!(
        "{TEST}: {shape:?}: the Mac's stage {up} bytes in {up_ms} ms ({:.1} MB/s), the VM's pull at the warm {down} bytes in {down_ms} ms ({:.1} MB/s; session stage --warm took {stage_ms} ms in all), the reopen's initialize on {vm} {} ms (Cursor waits {} s), the VM's full upload {full} bytes in {full_ms} ms ({:.1} MB/s); with the chat open, after a turn of {} ms: {memory}",
        rate(up, up_ms),
        rate(down, down_ms),
        init.as_millis(),
        LIVE_INIT_LIMIT.as_secs(),
        rate(full, full_ms),
        turn.ms
    );
    let out = chat.output();
    let mut outs = vec![&staged, &out, &exec, &synced];
    outs.extend(probe.as_ref());
    sweep_live(&live, &outs, &[]);
}

/// T9 S3 live (B6): the Mac cannot read the VM's objects, nor write one.
/// After a chat's turn landed in S3 (the chat left open until the turn's own
/// sync committed it, [`Chat::wait_for_sync`]; then the close), the Mac's
/// own runtime key (outside the gateway endpoint) is refused a GET of each
/// part (by its version and as the current one) and a PUT of the next
/// generation's base: 403 `AccessDenied` each, the bucket policy's denies.
/// The chat's objects are purged at the end ([`PurgeTranscripts`]). Three
/// Touch IDs: the chat's, the test process's runtime key, the purge.
#[test]
#[ignore = "live, S9's S3 store, starts a MicroVM and asks the model (three Touch IDs): AI_ENV_AWS_TESTS=1 make test-aws S3=1"]
fn live_s3_mac_cannot_read_vm_objects() {
    const TEST: &str = "live_s3_mac_cannot_read_vm_objects";
    if !s3_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[("suspend_on_close", toml::Value::Boolean(false))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s3-mac-reads");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    chat.turn("Reply with exactly OK");
    chat.wait_for_sync(&live, 0);
    let (code, close) = chat.close();
    assert_closed_well(TEST, &live, &chat, code, close);
    let session = chat.session.clone().expect("the chat's session id");
    let manifest = s3_manifest(TEST, &live, &session);
    let parts = manifest_parts(&manifest);
    assert!(!parts.is_empty(), "{TEST}: the turn landed in S3");
    let gen = manifest.get("gen").and_then(toml::Value::as_integer).unwrap_or(1);
    let answers = tokio::runtime::Runtime::new().unwrap().block_on(async {
        use ai_env_cli::bridge::s3::{presign, S3Method};
        let api = connect(&live.creds).await;
        let target = s3_target(&live);
        let mut answers = Vec::new();
        for (key, version) in &parts {
            answers.push((format!("GET {key} by its version"), mac_s3(&api, &target, S3Method::Get, key, version.as_deref(), Vec::new(), Vec::new()).await));
            answers.push((format!("GET {key}"), mac_s3(&api, &target, S3Method::Get, key, None, Vec::new(), Vec::new()).await));
        }
        let body = b"{\"type\":\"user\"}\n".to_vec();
        let sha = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(&body))
        };
        let next = format!("v1/{session}/vm/g{}/base", gen + 1);
        let headers = presign::write_headers(body.len() as u64, &sha, true).unwrap();
        answers.push((format!("PUT {next}"), mac_s3(&api, &target, S3Method::Put, &next, None, headers, body).await));
        answers
    });
    for (what, answer) in &answers {
        eprintln!("{TEST}: {what}: {answer:?}");
        assert_eq!(answer, &(403, Some("AccessDenied".to_string())), "{TEST}: {what}");
    }
    let out = chat.output();
    sweep_live(&live, &[&out], &[]);
}

// ---- S10: session continuity, live (part B: B3, `make test-aws S10=1`) ------------------------
//
// S10 wave 1c (L1). Chats of the real `ai-env-claude` in remote mode on S8's
// rig (`wrapper_world`, `Chat`; the setup-token sealed) against image 12.0,
// each in a fixture under this checkout's `target/s8/` (never the
// development chat): a close, a reopen and a closed lid (T10.2); a VM
// terminated mid-turn (T10.3) and after an edit past the last turn (T10.4
// (c)); a park at a permission prompt, then subagents across a move
// (T10.5); `session migrate` of a live chat (§C). With AI_ENV_AWS_SLOW=1 too
// (`make test-aws S10=1 SLOW=1`) the three wall tests: a migration between
// turns (T10.4 (a)), a reopen near the wall and one after it (T10.4 (b), the
// platform's wall recorded), a quarter of an hour each or a little more. The
// tests play the chat a step at a time (`Chat::send_user`,
// `read_until`, `held_permission`, `answer_permission`, `turn_to_result`),
// read the wrapper's stderr live, end a VM under a turn
// (`Chat::terminate_mid_turn`), stand in for a closed lid
// (`Chat::stop_for`), and ring the terminal's bell before each Touch ID
// they expect (`announce_touch_id`): one per chat and per `vm` command, one
// more per move to a new VM (M1), the test process's runtime key, once per
// process, when the first test builds its world (`live_world`, `LIVE_CREDS`;
// each test's count below includes it, as when it runs alone), and one per
// test for its chats' S3 objects (`PurgeTranscripts`). The evidence is read
// by the contracts' names (`remote::census_part`, `remote::audit_event`, the
// notes `remote::note_*` build). A test that needs neither the wall nor a
// migration runs its VMs with `max_duration_s = 1800` and
// `migrate_before_wall_s = 0` (`s10_world`): no wall and no migration's
// Touch ID inside it.

use ai_env_cli::bridge::migrate::MIGRATE_WAIT;
use ai_env_cli::bridge::registry::VmEntry;
use ai_env_cli::bridge::remote::link::{LossCause, MigrateTrigger};
use ai_env_cli::bridge::remote::{self, audit_event, census_part};
use ai_env_cli::wire::time::unix_now;

/// How long a turn that moves the chat may take: the move (its Touch ID, a
/// VM, the seed and the restore, within `MOVE_WINDOW`), then the turn.
const LIVE_MOVE_TURN_LIMIT: Duration = Duration::from_secs(480);
/// How long the wrapper's note of a loss may take once the VM is gone.
const LIVE_LOSS_NOTE_LIMIT: Duration = Duration::from_secs(120);
/// How long an old VM may take to end once the chat moved off it (its sync,
/// the terminate, TERMINATED).
const LIVE_OLD_VM_LIMIT: Duration = Duration::from_secs(180);

/// Whether S10's live tests run: [`live`], and AI_ENV_S10_TESTS=1 (`make test-aws S10=1`).
fn s10_live() -> bool {
    if !live() {
        return false;
    }
    if std::env::var("AI_ENV_S10_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_S10_TESTS=1 too (make test-aws S10=1) for S10's chats");
    false
}

/// [`s10_live`], and AI_ENV_AWS_SLOW=1 (`make test-aws S10=1 SLOW=1`): the three wall tests.
fn s10_slow_live() -> bool {
    if !s10_live() {
        return false;
    }
    if std::env::var("AI_ENV_AWS_SLOW").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_AWS_SLOW=1 too (make test-aws S10=1 SLOW=1) for the wall tests");
    false
}

/// [`wrapper_world`] for an S10 test that needs neither the wall nor a
/// migration: `[vm] max_duration_s = 1800` (no VM reaches its wall inside a
/// test) and `migrate_before_wall_s = 0` (no migration asks a Touch ID
/// nobody expects; `session migrate` still moves a chat), then `vm`'s keys.
fn s10_world(vm: &[(&str, toml::Value)]) -> Live {
    let mut keys = vec![("max_duration_s", toml::Value::Integer(1800)), ("migrate_before_wall_s", toml::Value::Integer(0))];
    keys.extend(vm.iter().cloned());
    wrapper_world(&keys)
}

/// The line [`announce_touch_id`] prints: the terminal's bell first.
fn touch_id_line(who: &str, why: &str) -> String {
    format!("\u{7}{who}: answer the Touch ID now: {why}")
}

/// Says on stderr, with the terminal's bell, that a Touch ID is due now and
/// why (S10, plan §G): a long test asks at moments the operator cannot
/// guess, and the dialog closes unanswered after 48 s.
fn announce_touch_id(who: &str, why: &str) {
    let _ = writeln!(std::io::stderr(), "{}", touch_id_line(who, why));
}

/// A word a chat is told and later asked for: `stem` and four characters of a fresh uuid.
fn live_word(stem: &str) -> String {
    format!("{stem}{}", uuid::Uuid::now_v7().simple().to_string().chars().rev().take(4).collect::<String>())
}

/// Whether `v` is claude's `can_use_tool` request for `tool`.
fn is_permission_for(v: &serde_json::Value, tool: &str) -> bool {
    v["type"] == "control_request" && v["request"]["subtype"] == "can_use_tool" && v["request"]["tool_name"] == tool
}

/// Whether `v` is claude's call of `tool` (an assistant frame's `tool_use`
/// block): what a turn shows of a command claude runs without asking
/// (claude 2.1.305 runs `sleep` and `echo` with no `can_use_tool`; part B,
/// 22 Oct). A test that waits for a tool to start takes either sign.
fn is_tool_use(v: &serde_json::Value, tool: &str) -> bool {
    v["type"] == "assistant" && v["message"]["content"].as_array().is_some_and(|blocks| blocks.iter().any(|b| b["type"] == "tool_use" && b["name"] == tool))
}

/// A Bash call is seen whether claude asked for it or ran it unasked, and
/// nothing else counts as one.
#[test]
fn a_bash_call_is_seen_asked_or_not() {
    let asked = serde_json::json!({"type": "control_request", "request_id": "r-1", "request": {"subtype": "can_use_tool", "tool_name": "Bash", "input": {}}});
    let ran = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "running"}, {"type": "tool_use", "id": "t-1", "name": "Bash", "input": {}}]}});
    let other = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t-2", "name": "Read", "input": {}}]}});
    let text = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "Bash"}]}});
    let seen = |v: &serde_json::Value| is_permission_for(v, "Bash") || is_tool_use(v, "Bash");
    assert!(seen(&asked) && seen(&ran) && !seen(&other) && !seen(&text));
}

/// Whether `v` is ai-env's informational line `text` (L3: `wire::claude::informational_line`).
fn is_note(v: &serde_json::Value, text: &str) -> bool {
    v["type"] == "system" && v["subtype"] == "informational" && v["content"] == text
}

/// The `moves` part's value (`readdress=<n>,respawn=<n>,migrate=<n>`,
/// contracts §4.1) as its three counts, in that order.
fn moves_of(value: &str) -> Option<[u32; 3]> {
    let mut counts = [0u32; 3];
    let mut parts = value.split(',');
    for (slot, kind) in counts.iter_mut().zip(["readdress", "respawn", "migrate"]) {
        *slot = parts.next()?.strip_prefix(kind)?.strip_prefix('=')?.parse().ok()?;
    }
    parts.next().is_none().then_some(counts)
}

/// `<forwarded>/<swallowed>` (the `inits` and `echoes` parts) as its two counts.
fn counts_of(value: &str) -> Option<(u32, u32)> {
    let (forwarded, swallowed) = value.split_once('/')?;
    Some((forwarded.parse().ok()?, swallowed.parse().ok()?))
}

/// A census row's moves ([`moves_of`]); `None` when no move started.
fn row_moves(row: &serde_json::Value) -> Option<[u32; 3]> {
    note_part(row, census_part::MOVES).as_deref().and_then(moves_of)
}

/// The audit rows of `event` the process `pid` wrote in the test's root (a wrapper's own).
fn audit_of(live: &Live, event: &str, pid: u32) -> Vec<serde_json::Value> {
    live_audit(live, event).into_iter().filter(|r| r["pid"].as_u64() == Some(u64::from(pid))).collect()
}

/// The `vms[]` of `session`'s row, oldest first ([`VmEntry`], read leniently).
fn vm_entries(test: &str, live: &Live, session: &str) -> Vec<VmEntry> {
    let row = ai_env_cli::bridge::registry::read(&live.paths, session).unwrap().unwrap_or_else(|| panic!("{test}: no session row of {session}"));
    row.vms.iter().filter_map(VmEntry::from_value).collect()
}

/// The move of `session` that the wrapper `pid` audited (contracts §4.2):
/// its `session_move` (`kind`, `why`'s key and word: `cause` or `trigger`,
/// from `vms.0`) and its `session_move_end` (`done`, from `vms.0` to
/// `vms.1`), both said and handed back for more checks.
fn moved_rows(test: &str, live: &Live, pid: u32, session: &str, kind: &str, why: (&str, &str), vms: (&str, &str)) -> (serde_json::Value, serde_json::Value) {
    let ((key, word), (from, to)) = (why, vms);
    let starts = audit_of(live, audit_event::SESSION_MOVE, pid);
    let start = starts
        .iter()
        .find(|r| r["detail"]["session"] == session && r["detail"]["kind"] == kind && r["detail"][key] == word && r["detail"]["from_vm"] == from)
        .cloned()
        .unwrap_or_else(|| panic!("{test}: no session_move ({kind}, {key} {word}, from {from}): {starts:?}"));
    let ends = audit_of(live, audit_event::SESSION_MOVE_END, pid);
    let end = ends
        .iter()
        .find(|r| r["detail"]["session"] == session && r["detail"]["kind"] == kind && r["detail"]["outcome"] == "done" && r["detail"]["from_vm"] == from && r["detail"]["to_vm"] == to)
        .cloned()
        .unwrap_or_else(|| panic!("{test}: no session_move_end ({kind}, done, from {from} to {to}): {ends:?}"));
    eprintln!("{test}: session_move {}\n{test}: session_move_end {}", start["detail"], end["detail"]);
    (start, end)
}

/// S10: polls `probe` every [`LIVE_SYNC_POLL`] until it answers, at most
/// `limit`: its answer. The test fails past it naming `what`, and at once on
/// a caught signal.
fn wait_for<T>(test: &str, what: &str, limit: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{test}: interrupted while waiting for {what}");
        if let Some(found) = probe() {
            eprintln!("{test}: {what}: after {} ms", t.elapsed().as_millis());
            return found;
        }
        assert!(t.elapsed() < limit, "{test}: {what}: not within {limit:?}");
        std::thread::sleep(LIVE_SYNC_POLL);
    }
}

/// S10: sleeps until the unix second `at` (a wall test waiting for its VM's
/// age), saying how long first; a caught signal fails the test at once.
fn sleep_until_unix(test: &str, what: &str, at: u64) {
    eprintln!("{test}: waiting {} s for {what}", at.saturating_sub(unix_now()));
    while unix_now() < at {
        assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{test}: interrupted while waiting for {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// GetMicrovm through the test process's runtime key, from a synchronous
/// test (S10: the closing suspend's SUSPENDED, a parked VM's, an old VM's
/// TERMINATED).
struct PlatformView {
    rt: tokio::runtime::Runtime,
    api: SdkMicrovmApi,
}

impl PlatformView {
    fn new(live: &Live) -> PlatformView {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let api = rt.block_on(connect(&live.creds));
        PlatformView { rt, api }
    }

    /// `vm`'s state as the platform says it: `TERMINATED` for one it no
    /// longer knows, the error (account ids masked) when it could not say.
    fn state(&self, vm: &str) -> String {
        match self.info(vm) {
            Ok(Some(info)) => info.state.as_str().to_string(),
            Ok(None) => VmState::Terminated.as_str().to_string(),
            Err(e) => format!("unknown: {e}"),
        }
    }

    /// `vm` as the platform says it, its `stateReason` and end time with
    /// it (T10.4: the wall's); `None` for one it no longer knows, the error
    /// (account ids masked) when it could not say.
    fn info(&self, vm: &str) -> Result<Option<ai_env_cli::bridge::api::VmInfo>, String> {
        match self.rt.block_on(self.api.get(vm)) {
            Ok(info) => Ok(Some(info)),
            Err(BridgeError::VmNotFound(_)) => Ok(None),
            Err(e) => Err(no_account(&e.to_string())),
        }
    }
}

/// Offline (S10): the census readers the live tests judge a move by, on
/// the parts as the pump writes them; and the Touch ID's bell.
#[test]
fn the_move_parts_read_as_the_census_writes_them() {
    assert_eq!(moves_of("readdress=1,respawn=0,migrate=2"), Some([1, 0, 2]));
    for bad in ["", "readdress=1", "readdress=1,respawn=0", "readdress=1,respawn=0,migrate=2,x=1", "respawn=0,readdress=1,migrate=2", "readdress=a,respawn=0,migrate=0", "readdress1,respawn=0,migrate=0"] {
        assert_eq!(moves_of(bad), None, "{bad}");
    }
    assert_eq!((counts_of("3/1"), counts_of("0/0")), (Some((3, 1)), Some((0, 0))));
    for bad in ["", "3", "3/", "/1", "a/1", "3/1/2"] {
        assert_eq!(counts_of(bad), None, "{bad}");
    }
    let row = serde_json::json!({"note": "vm:microvm-2; vm_how:started; moves:readdress=1,respawn=0,migrate=0; move_ms:5123; cut:at; inits:3/1; echoes:3/1; link_drops:0; carried:migrate"});
    assert_eq!(row_moves(&row), Some([1, 0, 0]), "the moves, never move_ms");
    assert_eq!(note_part(&row, census_part::MOVE_MS).as_deref(), Some("5123"));
    assert_eq!((note_part(&row, census_part::INITS).as_deref().and_then(counts_of), note_part(&row, census_part::ECHOES).as_deref().and_then(counts_of)), (Some((3, 1)), Some((3, 1))));
    assert_eq!(note_part(&row, census_part::CARRIED).as_deref(), Some("migrate"));
    assert_eq!(row_moves(&serde_json::json!({"note": "vm:microvm-1; link_drops:0"})), None, "no move started");
    let line = touch_id_line("t", "vm terminate microvm-1");
    assert!(line.starts_with('\u{7}') && line.ends_with("t: answer the Touch ID now: vm terminate microvm-1"), "{line:?}");
}

/// Offline (S10 F1): the purge is one `session forget <sid>... --purge` of
/// every session a test's root keeps transcript state of or whose row
/// keeps its transcript in S3, each once and sorted, and no command at all
/// for none; a local chat's row and a directory that names no session are
/// left out.
#[test]
fn the_purge_is_one_forget_of_every_session_or_none() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
    assert!(purged_sessions(&paths).is_empty() && purge_args(&[]).is_none(), "no session: no command");
    let (a, b, c, d) = ("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5a", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d");
    // a: transcript state and a row naming S3; b: the state alone; c: the row alone (its sync never committed).
    for sid in [a, b] {
        std::fs::create_dir_all(paths.transcript_dir(sid)).unwrap();
    }
    std::fs::create_dir_all(paths.transcripts().join("not-a-session")).unwrap();
    for (sid, home) in [(a, Some("s3")), (c, Some("s3")), (d, None)] {
        let row = ai_env_cli::bridge::registry::SessionRow { session_id: sid.to_string(), transcript_home: home.map(str::to_string), ..ai_env_cli::bridge::registry::SessionRow::default() };
        ai_env_cli::bridge::registry::write(&paths, &row).unwrap();
    }
    let sessions = purged_sessions(&paths);
    assert_eq!(sessions, [b, c, a], "each once, sorted; the local chat's row left out");
    assert_eq!(purge_args(&sessions).unwrap(), ["session", "forget", b, c, a, "--purge"], "one command for them all");
}

/// Offline (S10): the chat played a step at a time over a wrapper that is
/// `cat` (each line the test sends comes back as the wrapper's own, after a
/// line on stderr). The user line goes out with its uuid; `read_until`
/// records the turn (the line's echo but not the line itself, an init,
/// ai-env's note but not an informational line of claude's own, a withdrawn
/// request, a tool's use and its output) and answers
/// claude's requests (a `can_use_tool` allowed as asked under `AllowAll`,
/// any other with an error: both answers come back through `cat`); under
/// `Hold` a `can_use_tool` is handed back unanswered (`held_permission`)
/// until `answer_permission` denies it; `turn_to_result` ends at the result,
/// at once when it was read already; the stderr reads while the wrapper runs.
#[test]
fn the_split_chat_records_answers_and_holds_as_asked() {
    const TEST: &str = "the_split_chat_records_answers_and_holds_as_asked";
    let wait = Duration::from_secs(10);
    let child = std::process::Command::new("/bin/sh")
        .args(["-c", "echo 'said on stderr first' >&2; exec cat"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("sh runs");
    let mut chat = Chat::over(TEST, child);
    let t = Instant::now();
    while !chat.stderr_now().contains("said on stderr first") {
        assert!(t.elapsed() < wait, "the stderr is read while the wrapper runs: {:?}", chat.stderr_now());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(chat.child.try_wait(), Ok(None)), "still running");
    let uuid = chat.send_user("hello");
    let bash = serde_json::json!({"type": "control_request", "request_id": "r-1", "request": {"subtype": "can_use_tool", "tool_name": "Bash", "input": {"command": "ls"}}});
    for line in [
        serde_json::json!({"type": "system", "subtype": "init", "session_id": "s-1"}),
        serde_json::json!({"type": "user", "isReplay": true, "uuid": uuid, "message": {"role": "user", "content": "hello"}}),
        serde_json::json!({"type": "system", "subtype": "informational", "level": "warning", "content": "ai-env: a note"}),
        serde_json::json!({"type": "system", "subtype": "informational", "level": "info", "content": "a notice of claude's own"}),
        bash.clone(),
        serde_json::json!({"type": "control_request", "request_id": "r-2", "request": {"subtype": "mcp_message"}}),
        serde_json::json!({"type": "control_cancel_request", "request_id": "r-3"}),
        serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t-1", "name": "Bash", "input": {}}]}}),
        serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t-1", "content": "out-1"}]}}),
    ] {
        chat.send(&line);
    }
    // The answers come back through `cat` after the lines sent before them.
    let answered = chat.read_until(wait, Asks::AllowAll, |v| v["type"] == "control_response" && v["response"]["request_id"] == "r-2").expect("the error's answer comes back");
    assert_eq!(answered["response"]["subtype"], "error", "{answered}");
    let allowed = chat.stdout.split(|b| *b == b'\n').filter_map(|l| serde_json::from_slice::<serde_json::Value>(l).ok()).find(|v| v["type"] == "control_response" && v["response"]["request_id"] == "r-1").expect("the allow came back");
    assert_eq!((allowed["response"]["subtype"].as_str(), allowed["response"]["response"]["behavior"].as_str(), &allowed["response"]["response"]["updatedInput"]), (Some("success"), Some("allow"), &bash["request"]["input"]), "{allowed}");
    assert!(is_permission_for(&bash, "Bash") && !is_permission_for(&bash, "Read"));
    // Held: handed back unanswered, then denied.
    let ask = serde_json::json!({"type": "control_request", "request_id": "r-4", "request": {"subtype": "can_use_tool", "tool_name": "Write", "input": {"file_path": "x"}}});
    chat.send(&ask);
    let held = chat.held_permission(wait);
    assert_eq!(held["request_id"], "r-4");
    let to_r4 = |v: &serde_json::Value| v["type"] == "control_response" && v["response"]["request_id"] == "r-4";
    assert!(chat.read_until(Duration::from_millis(300), Asks::Hold, to_r4).is_none(), "nothing answered the held request");
    chat.answer_permission(&held, false);
    let denied = chat.read_until(wait, Asks::Hold, to_r4).expect("the denial comes back");
    assert_eq!((denied["response"]["subtype"].as_str(), denied["response"]["response"]["behavior"].as_str()), (Some("success"), Some("deny")), "{denied}");
    chat.send(&serde_json::json!({"type": "result", "subtype": "success", "is_error": false, "result": "done"}));
    let turn = chat.turn_to_result(&uuid, wait);
    assert_eq!((turn.uuid.as_str(), turn.result["result"].as_str(), turn.results, turn.echoes, turn.inits), (uuid.as_str(), Some("done"), 1, 1, 1), "the echo counted, the line itself not");
    assert_eq!((turn.asked, turn.used, turn.tool_output, turn.notes, turn.cancels), (vec!["Bash".to_string(), "Write".to_string()], vec!["Bash".to_string()], "out-1\n".to_string(), vec!["ai-env: a note".to_string()], vec!["r-3".to_string()]));
    assert_eq!(chat.session.as_deref(), Some("s-1"), "the newest init's session id");
    assert!(is_note(&serde_json::json!({"type": "system", "subtype": "informational", "content": "ai-env: a note"}), "ai-env: a note"));
    // A result read already: the turn ends at once.
    let again = chat.send_user("again");
    chat.send(&serde_json::json!({"type": "result", "subtype": "success", "is_error": false, "result": "twice"}));
    chat.read_until(wait, Asks::AllowAll, |v| v["type"] == "result").expect("the result");
    assert_eq!(chat.turn_to_result(&again, Duration::ZERO).result["result"], "twice");
    let (code, _) = chat.close();
    assert_eq!(code, Some(0), "cat ends at its stdin's close");
}

/// Offline (S10): the lid's stand-in stops the wrapper for its time and
/// continues it after; a chat whose wrapper is stopped still ends it by its
/// SIGTERM, continued first (a stopped process takes no TERM: the SIGKILL 3
/// s later would be all it got).
#[test]
fn a_stopped_wrapper_is_continued_then_ended_by_its_term() {
    use std::os::unix::process::ExitStatusExt as _;
    const TEST: &str = "a_stopped_wrapper_is_continued_then_ended_by_its_term";
    /// `ps`'s state letters of `pid` (`T` first: stopped).
    fn state(pid: u32) -> String {
        let o = std::process::Command::new("/bin/ps").args(["-o", "stat=", "-p", &pid.to_string()]).output().expect("ps runs");
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }
    let child = std::process::Command::new("/bin/cat").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("cat runs");
    let mut chat = Chat::over(TEST, child);
    let pid = chat.pid();
    let during = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        state(pid)
    });
    let t = Instant::now();
    chat.stop_for(Duration::from_millis(900));
    assert!(t.elapsed() >= Duration::from_millis(900), "{:?}", t.elapsed());
    let during = during.join().unwrap();
    assert!(during.starts_with('T'), "stopped meanwhile: {during:?}");
    assert!(!state(pid).starts_with('T'), "continued after: {:?}", state(pid));
    chat.send(&serde_json::json!({"type": "system", "subtype": "status"}));
    assert!(chat.read_until(Duration::from_secs(10), Asks::AllowAll, |v| v["subtype"] == "status").is_some(), "the wrapper runs on");
    chat.signal(libc::SIGSTOP);
    let t = Instant::now();
    while !state(pid).starts_with('T') {
        assert!(t.elapsed() < Duration::from_secs(5), "stopped again: {:?}", state(pid));
        std::thread::sleep(Duration::from_millis(20));
    }
    let t = Instant::now();
    let status = chat.end().expect("its exit");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "ended by its TERM, not the KILL: {status}");
    assert!(t.elapsed() < Duration::from_secs(2), "well before the KILL's 3 s: {:?}", t.elapsed());
}

/// T10.2 live: a chat lives through its close, its reopen and a closed lid.
/// A chat told a word closes (exit 0 within 1.5 s; its closing suspend
/// fired: `vm_suspend` by `close`, `fired`), and its VM goes to SUSPENDED
/// (GetMicrovm, the states on the way said). The reopen (`--resume`)
/// resumes that VM (`vm_how:resumed`, `transcript:kept`, `init_ms` under
/// 15 s) and recalls the word. Then a turn's Bash call (`sleep 30`) runs
/// while the wrapper is stopped for three minutes (SIGSTOP, then SIGCONT:
/// [`Chat::stop_for`], the lid's stand-in): the wrapper finds its socket
/// gone and reattaches (an `agent_reconnect` row of its own, `link_drops`
/// of 1 or more), and the turn's result comes through whole; the close is
/// exit 0 within 1.5 s again. Four Touch IDs: two chats, the test process's
/// runtime key, the purge. About six minutes.
#[test]
#[ignore = "live, S10, a close, a reopen and a closed lid's stand-in on one MicroVM (about six minutes; four Touch IDs: two chats, the test process's runtime key, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 make test-aws S10=1"]
fn live_s10_close_reopen_and_sleep() {
    const TEST: &str = "live_s10_close_reopen_and_sleep";
    // T10.2's lid, closed three minutes.
    const LID: Duration = Duration::from_secs(180);
    // The platform's suspend after the close, and the reopen's budget (plan T10.2: under 15 s).
    const SUSPEND_LIMIT: Duration = Duration::from_secs(90);
    const REOPEN_BUDGET_MS: u128 = 15_000;
    if !s10_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s10_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let platform = PlatformView::new(&live);
    let ws = s8_fixture(&live, "live-s10-close-reopen");
    let word = live_word("meadow");
    let mut first = Chat::open(TEST, &live, &ws, &[]);
    first.initialize();
    let told = first.turn(&format!("Remember this word for later: {word}. Reply with exactly OK"));
    assert_eq!(told.result["is_error"], false, "{TEST}: {}", told.result);
    let (code, close) = first.close();
    let row = assert_closed_well(TEST, &live, &first, code, close);
    let (vm, session) = (note_part(&row, census_part::VM).expect("the chat's VM"), first.session.clone().expect("the chat's session id"));
    let suspends: Vec<serde_json::Value> = audit_of(&live, "vm_suspend", first.pid()).into_iter().filter(|r| r["detail"]["by"] == "close" && r["detail"]["id"] == vm.as_str()).collect();
    assert!(suspends.iter().any(|r| r["detail"]["outcome"] == "fired"), "{TEST}: the closing suspend fired: {suspends:?}");
    let mut seen: Vec<String> = Vec::new();
    wait_for(TEST, &format!("{vm} SUSPENDED after the close"), SUSPEND_LIMIT, || {
        let state = platform.state(&vm);
        if seen.last() != Some(&state) {
            seen.push(state.clone());
        }
        (state == VmState::Suspended.as_str()).then_some(())
    });
    eprintln!("{TEST}: {vm} after the close: {}", seen.join(" > "));
    assert!(!seen.iter().any(|s| s == VmState::Terminating.as_str() || s == VmState::Terminated.as_str()), "{TEST}: the close only suspends: {seen:?}");
    let resume = format!("--resume={session}");
    let mut second = Chat::open(TEST, &live, &ws, &[&resume]);
    second.initialize();
    let recall = second.turn("Which word did I ask you to remember? Reply with the word only.");
    let answer = recall.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer {answer:?} lacks the word");
    // The lid: the wrapper stopped once the Bash call is allowed (or runs unasked: claude 2.1.305 asks nothing for a
    // sleep), the sleep running in the VM.
    let uuid = second.send_user("Run exactly this command with your Bash tool, then reply with its output only: sleep 30; echo slept");
    if second.read_until(LIVE_TURN_LIMIT, Asks::AllowAll, |v| is_permission_for(v, "Bash") || is_tool_use(v, "Bash")).is_none() {
        let err = second.stderr_now();
        panic!("{TEST}: no Bash call within {LIVE_TURN_LIMIT:?}; the wrapper's stderr: {err}");
    }
    // The allow reaches the VM and the sleep runs there: the lid closes on it.
    second.idle(Duration::from_secs(5));
    eprintln!("{TEST}: the Bash call allowed and running: the wrapper stopped for {LID:?}, the lid's stand-in");
    second.stop_for(LID);
    let slept = second.turn_to_result(&uuid, LIVE_TURN_LIMIT);
    assert_eq!(slept.result["is_error"], false, "{TEST}: the turn through the lid: {}", slept.result);
    assert!(slept.tool_output.contains("slept"), "{TEST}: the tool's output: {}", slept.tool_output);
    let (code, close) = second.close();
    let row = assert_closed_well(TEST, &live, &second, code, close);
    assert_eq!(
        (note_part(&row, census_part::VM).as_deref(), note_part(&row, census_part::VM_HOW).as_deref(), note_part(&row, census_part::TRANSCRIPT).as_deref()),
        (Some(vm.as_str()), Some("resumed"), Some("kept")),
        "{TEST}: the reopen resumed the chat's VM and kept its transcript"
    );
    let init_ms: u128 = note_part(&row, "init_ms").and_then(|ms| ms.parse().ok()).expect("init_ms");
    assert!(init_ms < REOPEN_BUDGET_MS, "{TEST}: the reopen's initialize took {init_ms} ms (budget {REOPEN_BUDGET_MS} ms; the legs: {:?})", note_part(&row, census_part::LEGS));
    let drops: u32 = note_part(&row, census_part::LINK_DROPS).and_then(|n| n.parse().ok()).unwrap_or(0);
    let reconnects = audit_of(&live, "agent_reconnect", second.pid());
    eprintln!("{TEST}: link_drops:{drops}; the reconnects' reasons: {:?}", reconnects.iter().map(|r| r["detail"]["reason"].clone()).collect::<Vec<_>>());
    assert!(drops >= 1 && !reconnects.is_empty(), "{TEST}: the wrapper reattached after the stop: link_drops:{drops}, {reconnects:?}");
    let (a, b) = (first.output(), second.output());
    sweep_live(&live, &[&a, &b], &[]);
}

/// T10.3 live: a VM terminated mid-turn moves its chat to a new one (a
/// re-address, M1's one Touch ID more). A chat told a word runs a Bash
/// `sleep 90` (under the Bash tool's 2-minute default timeout, which its
/// second run must not reach); once the call is allowed and running, `vm
/// terminate` ends the VM under the turn, both Touch IDs announced before
/// it. The wrapper tells the chat (`note_moving`, L3), moves it
/// (`note_continues`) and sends the interrupted line again: claude runs the
/// turn again (the tool is idempotent), and the host gets one echo and one
/// result of that line. The census counts the move
/// (`moves:readdress=1,respawn=0,migrate=0`, `move_ms`) and one swallowed
/// init and echo (`inits:<n>/1`, `echoes:<n>/1`); the audit has
/// `session_move` (`readdress`, `vm_gone`, from the old VM) and
/// `session_move_end` (`done`, to the new VM, `touchid` `asked`); the
/// session row's `vms[]` gains the new VM (`readdress:vm_gone`); and the
/// next turn, on the new VM, recalls the word. Five Touch IDs: the chat, the
/// test process's runtime key, the terminate, the move, the purge. About
/// eight minutes.
#[test]
#[ignore = "live, S10, a MicroVM terminated mid-turn and its chat moved to a new one (about eight minutes; five Touch IDs: the chat, the test process's runtime key, the terminate, the move, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 make test-aws S10=1"]
fn live_s10_terminate_mid_turn_readdresses() {
    const TEST: &str = "live_s10_terminate_mid_turn_readdresses";
    // The sleep's turn: its first run cut by the terminate, the move, then its second run whole.
    const SLEEP_TURN_LIMIT: Duration = Duration::from_secs(600);
    if !s10_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s10_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s10-terminate-mid-turn");
    let word = live_word("lighthouse");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let told = chat.turn(&format!("Remember this word for later: {word}. Reply with exactly OK"));
    assert_eq!(told.result["is_error"], false, "{TEST}: {}", told.result);
    let vm1 = chat.session_vm(&live);
    let uuid = chat.send_user("Run exactly this command with your Bash tool, then reply with its output only: sleep 90; echo slept");
    if chat.read_until(LIVE_TURN_LIMIT, Asks::AllowAll, |v| is_permission_for(v, "Bash") || is_tool_use(v, "Bash")).is_none() {
        let err = chat.stderr_now();
        panic!("{TEST}: no Bash call within {LIVE_TURN_LIMIT:?}; the wrapper's stderr: {err}");
    }
    // The sleep runs in the VM: the VM ends under it.
    chat.idle(Duration::from_secs(5));
    let terminate = chat.terminate_mid_turn(&live, &vm1, Some(&format!("right after vm terminate's: the move off {vm1}, the setup-token for the new VM (M1)")));
    let turn = chat.turn_to_result(&uuid, SLEEP_TURN_LIMIT);
    let vm2 = chat.session_vm(&live);
    eprintln!(
        "{TEST}: the turn ended after {} ms on {vm2}: notes {:?}, asked {:?}, withdrawn {:?}, echoes {}, inits {}, results {}; the wrapper's stderr so far:\n{}",
        turn.ms,
        turn.notes,
        turn.asked,
        turn.cancels,
        turn.echoes,
        turn.inits,
        turn.results,
        chat.stderr_now()
    );
    assert_eq!(turn.result["is_error"], false, "{TEST}: the turn sent again: {}", turn.result);
    assert!(turn.tool_output.contains("slept"), "{TEST}: the tool's second run: {}", turn.tool_output);
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    assert_eq!(turn.notes, [remote::note_moving(&vm1, LossCause::VmGone), remote::note_continues(&vm2)], "{TEST}: the move's notes");
    assert_eq!((turn.echoes, turn.results), (1, 1), "{TEST}: one echo and one result of the line sent again");
    let recall = chat.turn("Which word did I ask you to remember? Reply with the word only.");
    let answer = recall.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer on the new VM {answer:?} lacks the word");
    assert_eq!(chat.session_vm(&live), vm2, "{TEST}: the next turn ran on the new VM");
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([1, 0, 0]), "{TEST}: one re-address in the census");
    assert!(note_part(&row, census_part::MOVE_MS).is_some(), "{TEST}: the move's time in the census");
    let swallowed = |part: &str| note_part(&row, part).as_deref().and_then(counts_of).map(|(_, s)| s);
    assert_eq!((swallowed(census_part::INITS), swallowed(census_part::ECHOES)), (Some(1), Some(1)), "{TEST}: the second init and echo of the line sent again were swallowed");
    let session = chat.session.clone().expect("the chat's session id");
    let (_, end) = moved_rows(TEST, &live, chat.pid(), &session, "readdress", ("cause", "vm_gone"), (&vm1, &vm2));
    assert_eq!(end["detail"]["touchid"].as_str(), Some("asked"), "{TEST}: the move asked its Touch ID (M1)");
    let entries = vm_entries(TEST, &live, &session);
    assert!(entries.iter().any(|e| e.vm == vm1) && entries.iter().any(|e| e.vm == vm2 && e.why == "readdress:vm_gone"), "{TEST}: the row's vms[]: {entries:?}");
    let out = chat.output();
    sweep_live(&live, &[&out, &terminate], &[]);
}

/// T10.4 (c) live: an edit made after the last turn is the documented loss
/// (L6, L7). A turn appends to README.md in the VM (Bash), and its code-out
/// fetch records the edit (a `box/wip/*` ref on the Mac); then `vm exec`
/// writes `late.txt` there and, 10 s later, `vm terminate` ends the VM with
/// the chat idle: the wrapper tells the chat it moves with the next message
/// (`note_move_at_next`, L5), and the next message moves it
/// (`note_continues`; `session_move_end` `done`, its seed `box`: the dead
/// VM's fetch record). On the new VM README.md holds the turn's edit and
/// `late.txt` is absent, as in the Mac's newest `box/wip/*`: files are as of
/// the last turn's end. Six Touch IDs: the chat, the test process's runtime
/// key, `vm exec`, the terminate, the move, the purge. About six minutes.
#[test]
#[ignore = "live, S10, a MicroVM terminated after an edit made past the last turn (about six minutes; six Touch IDs: the chat, the test process's runtime key, vm exec, the terminate, the move, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 make test-aws S10=1"]
fn live_s10_terminate_after_edit() {
    const TEST: &str = "live_s10_terminate_after_edit";
    if !s10_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s10_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s10-terminate-after-edit");
    let path = ws.display().to_string();
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let fetched = live_audit(&live, audit_event::CODEOUT_FETCH).len();
    let edit = chat.turn("Run exactly this command with your Bash tool, then reply with its output only: printf 'edited in the turn\\n' >> README.md && tail -n 1 README.md");
    assert_eq!(edit.result["is_error"], false, "{TEST}: {}", edit.result);
    assert!(edit.tool_output.contains("edited in the turn"), "{TEST}: the turn's edit: {}", edit.tool_output);
    // The turn's code-out fetch records the edit before anything else happens in the VM.
    chat.wait_for("the turn's codeout_fetch row", LIVE_SYNC_LIMIT, Asks::AllowAll, || (live_audit(&live, audit_event::CODEOUT_FETCH).len() > fetched).then_some(()));
    let newest_wip = || fixture_git(&ws, &["for-each-ref", "--sort=-refname", "--format=%(refname)", "refs/remotes/box/wip/"]).lines().next().map(str::to_string);
    let wip = newest_wip().unwrap_or_else(|| panic!("{TEST}: no box/wip ref after the turn's fetch"));
    assert!(fixture_git(&ws, &["show", &format!("{wip}:README.md")]).contains("edited in the turn"), "{TEST}: {wip} holds the turn's edit");
    let vm1 = chat.session_vm(&live);
    announce_touch_id(TEST, &format!("vm exec in {vm1}: late.txt, after the last turn"));
    let (_, late) = vm_sh(TEST, &live, &vm1, &path, "printf 'written after the turn\\n' > late.txt");
    chat.idle(Duration::from_secs(10));
    let terminate = chat.terminate_mid_turn(&live, &vm1, None);
    // Idle: the move waits for the next message (L5), and the note says so.
    let note = remote::note_move_at_next(&vm1, LossCause::VmGone);
    if chat.read_until(LIVE_LOSS_NOTE_LIMIT, Asks::AllowAll, |v| is_note(v, &note)).is_none() {
        let err = chat.stderr_now();
        panic!("{TEST}: no note within {LIVE_LOSS_NOTE_LIMIT:?} that the chat moves with the next message ({note:?}); the wrapper's stderr: {err}");
    }
    announce_touch_id(TEST, &format!("the move off {vm1} with the next message: the setup-token for the new VM (M1)"));
    let look = chat.turn_within("Run exactly this command with your Bash tool, then reply with its output only: tail -n 1 README.md; ls", LIVE_MOVE_TURN_LIMIT);
    assert_eq!(look.result["is_error"], false, "{TEST}: {}", look.result);
    let vm2 = chat.session_vm(&live);
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    assert!(look.notes.contains(&remote::note_continues(&vm2)), "{TEST}: the notes: {:?}", look.notes);
    assert!(look.tool_output.contains("edited in the turn"), "{TEST}: the turn's edit is on the new VM: {}", look.tool_output);
    assert!(!look.tool_output.lines().any(|l| l.trim() == "late.txt"), "{TEST}: late.txt, written after the last turn, is the documented loss: {}", look.tool_output);
    let newest = newest_wip().unwrap_or_else(|| panic!("{TEST}: no box/wip ref"));
    assert!(!fixture_git(&ws, &["ls-tree", "-r", "--name-only", &newest]).lines().any(|n| n == "late.txt"), "{TEST}: the Mac's newest wip ({newest}) lacks late.txt");
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([1, 0, 0]), "{TEST}: one re-address in the census");
    let session = chat.session.clone().expect("the chat's session id");
    let (_, end) = moved_rows(TEST, &live, chat.pid(), &session, "readdress", ("cause", "vm_gone"), (&vm1, &vm2));
    assert_eq!((end["detail"]["seed"].as_str(), end["detail"]["touchid"].as_str()), (Some("box"), Some("asked")), "{TEST}: the seed is the dead VM's fetch record (L7); the move asked its Touch ID (M1)");
    let out = chat.output();
    sweep_live(&live, &[&out, &late, &terminate], &[]);
}

/// T10.5 live: a chat parked at a permission prompt, then subagents across a
/// move. With `[vm] park_after_s = 30` (M5's floor), a turn's Bash call is
/// left unanswered: the session parks at the prompt (`session_park`, `why`
/// `prompt`), and the platform suspends the silent VM after its
/// `max_idle_s` (GetMicrovm: SUSPENDED, the prompt still open). The answer
/// unparks the session (`session_unpark` by `control_response`, the VM found
/// `suspended`; no Touch ID) and the tool runs. A turn that starts a
/// subagent lands its files in S3 (the Mac's manifest lists
/// `<sid>/subagents/…`; none is on the Mac). `vm terminate`, then the next
/// message moves the chat (a note of the loss, at it or at that message as
/// the session was parked or not, then `note_continues`; M1's Touch ID);
/// the subagents' files are pulled into the new VM after its spawn (a
/// `transcript_pull` row each), and the chat's own `ls` lists them there. A
/// reopen (`--resume`) keeps the transcript on that VM (`transcript:kept`).
/// Six Touch IDs: two chats, the test process's runtime key, the terminate,
/// the move, the purge. About fourteen minutes.
#[test]
#[ignore = "live, S10, a chat parked at a permission prompt on a suspended MicroVM, then subagents across a move (about fourteen minutes; six Touch IDs: two chats, the test process's runtime key, the terminate, the move, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 make test-aws S10=1"]
fn live_s10_parked_at_prompt_then_subagents() {
    const TEST: &str = "live_s10_parked_at_prompt_then_subagents";
    // M5's floor (30..=3600): the park comes half a minute after the prompt.
    const PARK_AFTER_S: u32 = 30;
    if !s10_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s10_world(&[("park_after_s", toml::Value::Integer(i64::from(PARK_AFTER_S)))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let platform = PlatformView::new(&live);
    let ws = s8_fixture(&live, "live-s10-parked-prompt");
    let slug = ai_env_cli::wire::slug::project_dir_name(&ws).expect("the fixture's project directory name");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let pid = chat.pid();
    let uuid = chat.send_user("Run exactly this command with your Bash tool, then reply with its output only: touch parked.txt && ls parked.txt");
    let asked = chat.held_permission(LIVE_TURN_LIMIT);
    let vm1 = chat.session_vm(&live);
    eprintln!("{TEST}: the Bash call on {vm1} left unanswered: the session parks at the prompt, then the platform suspends the VM");
    let parked = chat.wait_for("the park at the prompt", Duration::from_secs(u64::from(PARK_AFTER_S) + 120), Asks::Hold, || {
        audit_of(&live, audit_event::SESSION_PARK, pid).into_iter().find(|r| r["detail"]["why"] == "prompt" && r["detail"]["vm"] == vm1.as_str())
    });
    eprintln!("{TEST}: {}", parked["detail"]);
    let suspend_limit = Duration::from_secs(u64::from(live.cfg.vm.max_idle_s) + 180);
    chat.wait_for(&format!("{vm1} SUSPENDED with the prompt open"), suspend_limit, Asks::Hold, || (platform.state(&vm1) == VmState::Suspended.as_str()).then_some(()));
    chat.answer_permission(&asked, true);
    let ran = chat.turn_to_result(&uuid, LIVE_TURN_LIMIT);
    assert_eq!(ran.result["is_error"], false, "{TEST}: the turn once answered: {}", ran.result);
    assert!(ran.tool_output.lines().any(|l| l.trim() == "parked.txt"), "{TEST}: the tool ran once answered: {}", ran.tool_output);
    let unparks = audit_of(&live, audit_event::SESSION_UNPARK, pid);
    assert!(unparks.iter().any(|r| r["detail"]["by"] == "control_response" && r["detail"]["vm_state"] == "suspended"), "{TEST}: the answer unparked the session from a suspended VM: {unparks:?}");
    // A subagent: its files land in S3 with the turn's sync, never on the Mac.
    let session = chat.session.clone().expect("the chat's session id");
    let task = chat.turn("Use your Task tool once: start one general-purpose subagent whose only job is to reply with exactly the word READY. Then reply with exactly DONE.");
    assert_eq!(task.result["is_error"], false, "{TEST}: the subagent's turn: {}", task.result);
    eprintln!("{TEST}: the subagent's turn used {:?}", task.used);
    let subagents = format!("{session}/subagents/");
    let files = chat.wait_for("the subagents' files in the Mac's manifest", LIVE_SYNC_LIMIT, Asks::AllowAll, || {
        let m = ai_env_cli::bridge::s3::manifest::read(&live.paths, &session).ok().flatten()?;
        let names: Vec<String> = m.files.iter().filter(|f| f.rel.contains(&subagents)).filter_map(|f| f.rel.rsplit('/').next().map(str::to_string)).collect();
        (!names.is_empty()).then_some(names)
    });
    assert!(!mac_projects().join(&slug).join(&session).exists(), "{TEST}: the subagents' files never reach the Mac (S9 M2)");
    let terminate = chat.terminate_mid_turn(&live, &vm1, None);
    // Idle, the loss's note comes at once (L5); parked, at the next message, which unparks into the gone VM.
    chat.idle(Duration::from_secs(15));
    let mut notes = std::mem::take(&mut chat.turn.notes);
    announce_touch_id(TEST, &format!("the move off {vm1} with the next message: the setup-token for the new VM (M1)"));
    let moved = chat.turn_within("Reply with exactly OK", LIVE_MOVE_TURN_LIMIT);
    assert_eq!(moved.result["is_error"], false, "{TEST}: the turn that moved the chat: {}", moved.result);
    notes.extend(moved.notes.iter().cloned());
    let vm2 = chat.session_vm(&live);
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    let lost = [remote::note_move_at_next(&vm1, LossCause::VmGone), remote::note_moving(&vm1, LossCause::VmGone)];
    assert!(notes.iter().any(|n| lost.contains(n)) && notes.contains(&remote::note_continues(&vm2)), "{TEST}: the move's notes: {notes:?}");
    // The subagents' files follow the chat: pulled into the new VM after its spawn, one row each beside the transcript's.
    let pulls_into = |vm: &str| live_audit(&live, audit_event::TRANSCRIPT_PULL).into_iter().filter(|r| r["detail"]["session"] == session.as_str() && r["detail"]["vm"] == vm && r["detail"]["outcome"] == "written").count();
    chat.wait_for("the subagents' files pulled into the new VM", LIVE_OLD_VM_LIMIT, Asks::AllowAll, || (pulls_into(&vm2) > files.len()).then_some(()));
    let listing = chat.turn(&format!("Run exactly this command with your Bash tool, then reply with its output only: ls \"$HOME/.claude/projects/{slug}/{session}/subagents\""));
    for name in &files {
        assert!(listing.tool_output.lines().any(|l| l.trim() == name), "{TEST}: {name} on the new VM: {}", listing.tool_output);
    }
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([1, 0, 0]), "{TEST}: the move in the census");
    eprintln!(
        "{TEST}: the census's parks: park:{:?} parked_s:{:?} unpark_ms:{:?} unpark_resumed:{:?} close_parked:{:?}",
        note_part(&row, census_part::PARK),
        note_part(&row, census_part::PARKED_S),
        note_part(&row, census_part::UNPARK_MS),
        note_part(&row, census_part::UNPARK_RESUMED),
        note_part(&row, census_part::CLOSE_PARKED)
    );
    let resume = format!("--resume={session}");
    let mut again = Chat::open(TEST, &live, &ws, &[&resume]);
    again.initialize();
    let ok = again.turn("Reply with exactly OK");
    assert_eq!(ok.result["is_error"], false, "{TEST}: the reopened chat's turn: {}", ok.result);
    let (code, close) = again.close();
    let reopened = assert_closed_well(TEST, &live, &again, code, close);
    assert_eq!(
        (note_part(&reopened, census_part::VM).as_deref(), note_part(&reopened, census_part::TRANSCRIPT).as_deref()),
        (Some(vm2.as_str()), Some("kept")),
        "{TEST}: the reopen kept the moved chat on its VM"
    );
    let (a, b) = (chat.output(), again.output());
    sweep_live(&live, &[&a, &b, &terminate], &[]);
}

/// `session migrate` live (§C, contracts §7.1): a live chat moved to a new
/// VM on request. A chat told a word appends to README.md in the VM (Bash),
/// its code-out fetch done; then `ai-env session migrate <sid> --json`
/// signals its wrapper, which prepares a new VM (`note_migrating`, the
/// setup-token's Touch ID there) and switches at once, the chat being idle:
/// the command answers `done` (`how` `live`, from the old VM to the new);
/// the audit has the request (`session_migrate_request`, `live`, the
/// wrapper's pid) and the move by its nonce (`session_move` `migrate`,
/// `command`; `session_move_end` `done`, `touchid` `asked`); the wrapper
/// ends the old VM (`terminated_by` `migrate`, its row `leaving_for` the
/// new); the row's `vms[]` gains `migrate:command`; the census says
/// `moves:readdress=0,respawn=0,migrate=1`; and the next turn, on the new
/// VM, recalls the word and finds the edit. The wall's migration is off
/// here ([`s10_world`]), which never stops a command's. Four Touch IDs: the
/// chat, the test process's runtime key, the move's in its wrapper, the
/// purge. About five minutes.
#[test]
#[ignore = "live, S10, session migrate of a live chat to a new MicroVM (about five minutes; four Touch IDs: the chat, the test process's runtime key, the move's in its wrapper, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 make test-aws S10=1"]
fn live_s10_session_migrate() {
    const TEST: &str = "live_s10_session_migrate";
    if !s10_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s10_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s10-session-migrate");
    let word = live_word("compass");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let fetched = live_audit(&live, audit_event::CODEOUT_FETCH).len();
    let told = chat.turn(&format!("Remember this word for later: {word}. Then run exactly this command with your Bash tool: printf 'edited before the move\\n' >> README.md. Reply with exactly OK"));
    assert_eq!(told.result["is_error"], false, "{TEST}: {}", told.result);
    chat.wait_for("the turn's codeout_fetch row", LIVE_SYNC_LIMIT, Asks::AllowAll, || (live_audit(&live, audit_event::CODEOUT_FETCH).len() > fetched).then_some(()));
    let (vm1, session) = (chat.session_vm(&live), chat.session.clone().expect("the chat's session id"));
    announce_touch_id(TEST, &format!("session migrate {session}: its wrapper (pid {}) asks for the setup-token of the new VM", chat.pid()));
    let migrated = ai_env_live_within(&live, &["session", "migrate", &session, "--json"], MIGRATE_WAIT + Duration::from_secs(60));
    assert_eq!(migrated.status.code(), Some(0), "{TEST}: session migrate: {}", String::from_utf8_lossy(&migrated.stdout));
    let v: serde_json::Value = serde_json::from_slice(&migrated.stdout).unwrap_or_else(|e| panic!("{TEST}: session migrate --json ({e}): {}", String::from_utf8_lossy(&migrated.stdout)));
    assert_eq!((v["session"].as_str(), v["outcome"].as_str(), v["how"].as_str(), v["from_vm"].as_str()), (Some(session.as_str()), Some("done"), Some("live"), Some(vm1.as_str())), "{TEST}: {v}");
    let vm2 = v["to_vm"].as_str().unwrap_or_else(|| panic!("{TEST}: no to_vm: {v}")).to_string();
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    // The chat's lines meanwhile: phase A's note, then the moved generation's.
    chat.idle(Duration::from_secs(5));
    let notes = std::mem::take(&mut chat.turn.notes);
    let asked = MigrateTrigger::Command { nonce: String::new() };
    assert!(notes.contains(&remote::note_migrating(&vm1, &asked)) && notes.contains(&remote::note_continues(&vm2)), "{TEST}: the move's notes: {notes:?}");
    let requests: Vec<serde_json::Value> = live_audit(&live, audit_event::SESSION_MIGRATE_REQUEST).into_iter().filter(|r| r["detail"]["session"] == session.as_str()).collect();
    let [request] = requests.as_slice() else { panic!("{TEST}: one request: {requests:?}") };
    let wrapper = chat.pid().to_string();
    assert_eq!((request["detail"]["how"].as_str(), request["detail"]["wrapper_pid"].as_str()), (Some("live"), Some(wrapper.as_str())), "{TEST}: {request}");
    let nonce = request["detail"]["nonce"].as_str().unwrap_or_default().to_string();
    let (start, end) = moved_rows(TEST, &live, chat.pid(), &session, "migrate", ("trigger", "command"), (&vm1, &vm2));
    assert_eq!(
        (start["detail"]["request"].as_str(), end["detail"]["request"].as_str(), end["detail"]["touchid"].as_str()),
        (Some(nonce.as_str()), Some(nonce.as_str()), Some("asked")),
        "{TEST}: the move answers the request by its nonce, its Touch ID asked in the wrapper"
    );
    let old = chat.wait_for(&format!("{vm1} terminated by the migration"), LIVE_OLD_VM_LIMIT, Asks::AllowAll, || vm_rows::read_row(&live.paths, &vm1).ok().flatten().filter(|r| r.status == RowStatus::Terminated));
    assert_eq!((old.terminated_by.as_deref(), old.leaving_for.as_deref()), (Some("migrate"), Some(vm2.as_str())), "{TEST}: the old VM's row");
    let look = chat.turn("Which word did I ask you to remember? Then run exactly this command with your Bash tool: tail -n 1 README.md. Reply with the word and that line.");
    let answer = look.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer on the new VM {answer:?} lacks the word");
    assert!(look.tool_output.contains("edited before the move"), "{TEST}: the edit came along: {}", look.tool_output);
    assert_eq!(chat.session_vm(&live), vm2, "{TEST}: the next turn ran on the new VM");
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([0, 0, 1]), "{TEST}: one migration in the census");
    let entries = vm_entries(TEST, &live, &session);
    assert!(entries.iter().any(|e| e.vm == vm2 && e.why == "migrate:command"), "{TEST}: the row's vms[]: {entries:?}");
    let out = chat.output();
    sweep_live(&live, &[&out, &migrated], &[]);
}

/// T10.4 (a) live, SLOW: the wall migration between turns. In
/// [`wrapper_world`]'s 900 s wall with 300 s before it
/// (`[vm].migrate_before_wall_s`), a chat told a word appends to README.md
/// in the VM (uncommitted), then takes a short turn every two minutes. Once
/// the VM has less than 300 s of its wall left, a turn's result starts the
/// migration (`note_migrating`; its Touch ID announced), which switches
/// with the chat idle: `session_move` (`migrate`, `wall`) and
/// `session_move_end` (`done`, `touchid` `asked`), every turn's result
/// whole before it; the old VM ends (`terminated_by` `migrate`,
/// `leaving_for` the new; the platform: TERMINATED); the row's `vms[]`
/// gains `migrate:wall`; the census says
/// `moves:readdress=0,respawn=0,migrate=1`; and the next turn, on the new
/// VM, recalls the word and finds the edit. Four Touch IDs: the chat, the
/// migration's, the test process's runtime key, the purge. About thirteen
/// minutes.
#[test]
#[ignore = "live, S10, a wall migration between turns (about thirteen minutes; four Touch IDs: the chat, the migration, the test process's runtime key, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 AI_ENV_AWS_SLOW=1 make test-aws S10=1 SLOW=1"]
fn live_s10_wall_migration() {
    const TEST: &str = "live_s10_wall_migration";
    // A short turn this often until the migration starts.
    const EVERY: Duration = Duration::from_secs(120);
    if !s10_slow_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let margin = live.cfg.vm.migrate_margin().expect("wrapper_world's [vm] migrates 300 s before its 900 s wall");
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let platform = PlatformView::new(&live);
    let ws = s8_fixture(&live, "live-s10-wall-migration");
    let word = live_word("harvest");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let told = chat.turn(&format!("Remember this word for later: {word}. Then run exactly this command with your Bash tool: printf 'edited before the wall\\n' >> README.md. Reply with exactly OK"));
    assert_eq!(told.result["is_error"], false, "{TEST}: {}", told.result);
    let (vm1, session, pid) = (chat.session_vm(&live), chat.session.clone().expect("the chat's session id"), chat.pid());
    let wall = vm_rows::read_row(&live.paths, &vm1).unwrap().and_then(|r| r.wall_deadline).unwrap_or_else(|| panic!("{TEST}: {vm1}'s row names no wall"));
    eprintln!("{TEST}: {vm1}'s wall in {} s; the migration is due in its last {margin} s", wall.saturating_sub(unix_now()));
    // A turn's result starts phase A once the wall is near: its note first, then its Touch ID.
    let note = remote::note_migrating(&vm1, &MigrateTrigger::Wall { left_s: 0 });
    let mut n = 0u32;
    loop {
        n += 1;
        assert!(unix_now() < wall, "{TEST}: {vm1}'s wall passed with no migration");
        let turn = chat.turn(&format!("Reply with exactly OK {n}"));
        assert_eq!(turn.result["is_error"], false, "{TEST}: turn {n}, whole whatever the wall: {}", turn.result);
        if turn.notes.contains(&note) || chat.read_until(Duration::from_secs(5), Asks::AllowAll, |v| is_note(v, &note)).is_some() {
            break;
        }
        chat.idle(EVERY);
        // A note later than that came during the pause: the next turn would start its record over.
        if chat.turn.notes.contains(&note) {
            break;
        }
    }
    announce_touch_id(TEST, &format!("the migration off {vm1} before its wall: the setup-token for the new VM (M1)"));
    let ended = chat.wait_for("the migration's end", remote::MOVE_WINDOW + Duration::from_secs(120), Asks::AllowAll, || {
        audit_of(&live, audit_event::SESSION_MOVE_END, pid).into_iter().find(|r| r["detail"]["kind"] == "migrate")
    });
    let vm2 = ended["detail"]["to_vm"].as_str().unwrap_or_default().to_string();
    let (_, end) = moved_rows(TEST, &live, pid, &session, "migrate", ("trigger", "wall"), (&vm1, &vm2));
    assert_eq!(end["detail"]["touchid"].as_str(), Some("asked"), "{TEST}: the migration asked its Touch ID (M1)");
    let old = chat.wait_for(&format!("{vm1} terminated by the migration"), LIVE_OLD_VM_LIMIT, Asks::AllowAll, || vm_rows::read_row(&live.paths, &vm1).ok().flatten().filter(|r| r.status == RowStatus::Terminated));
    assert_eq!((old.terminated_by.as_deref(), old.leaving_for.as_deref()), (Some("migrate"), Some(vm2.as_str())), "{TEST}: the old VM's row");
    // The note goes out just before its `session_move_end`, which the waits above may have found before reading it (I2).
    let continues = remote::note_continues(&vm2);
    if !chat.turn.notes.contains(&continues) {
        let _ = chat.read_until(LIVE_LOSS_NOTE_LIMIT, Asks::AllowAll, |v| is_note(v, &continues));
    }
    let notes = std::mem::take(&mut chat.turn.notes);
    assert!(notes.contains(&continues), "{TEST}: the notes since the last turn: {notes:?}");
    wait_for(TEST, &format!("{vm1} TERMINATED on the platform"), LIVE_OLD_VM_LIMIT, || (platform.state(&vm1) == VmState::Terminated.as_str()).then_some(()));
    let look = chat.turn("Which word did I ask you to remember? Then run exactly this command with your Bash tool: tail -n 1 README.md. Reply with the word and that line.");
    let answer = look.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer on the new VM {answer:?} lacks the word");
    assert!(look.tool_output.contains("edited before the wall"), "{TEST}: the uncommitted edit came along: {}", look.tool_output);
    assert_eq!(chat.session_vm(&live), vm2, "{TEST}: the next turn ran on the new VM");
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([0, 0, 1]), "{TEST}: one migration in the census");
    let entries = vm_entries(TEST, &live, &session);
    assert!(entries.iter().any(|e| e.vm == vm2 && e.why == "migrate:wall"), "{TEST}: the row's vms[]: {entries:?}");
    let out = chat.output();
    sweep_live(&live, &[&out], &[]);
}

/// T10.4 (b) live, SLOW: a reopen near the wall carries the chat to a new
/// VM first. In [`wrapper_world`]'s 900 s wall with 300 s before it, a chat
/// told a word appends to README.md in the VM (uncommitted; its code-out
/// fetch records it) and closes; once its VM has a minute less than that
/// margin left, the chat reopens (`--resume`): P0 to P4 carry it to a new
/// VM (`carried:migrate` and `moves:readdress=0,respawn=0,migrate=1` in the
/// census; `session_move` `migrate`, `reopen`, generation 1;
/// `session_move_end` `done`; `vms[]` `migrate:reopen`), the turn on the new
/// VM recalls the word and finds the edit (the last turn's WIP), and the old
/// VM is ended with the chat still open (`terminated_by` `migrate`, in the
/// wrapper's background as phase B does; the platform: TERMINATED). The
/// plan's reopen after the wall is [`live_s10_reopen_after_wall`]'s.
/// Four Touch IDs: two chats, the test process's runtime key, the purge.
/// About thirteen minutes.
#[test]
#[ignore = "live, S10, a reopen near the wall carried to a new MicroVM (about thirteen minutes; four Touch IDs: two chats, the test process's runtime key, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 AI_ENV_AWS_SLOW=1 make test-aws S10=1 SLOW=1"]
fn live_s10_reopen_near_wall() {
    const TEST: &str = "live_s10_reopen_near_wall";
    // How far inside the margin the reopen comes: room for the carry's resume, fetch and sync of the old VM.
    const INSIDE_S: u64 = 60;
    if !s10_slow_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let margin = u64::from(live.cfg.vm.migrate_margin().expect("wrapper_world's [vm] migrates 300 s before its 900 s wall"));
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let platform = PlatformView::new(&live);
    let ws = s8_fixture(&live, "live-s10-reopen-near-wall");
    let word = live_word("orchard");
    let mut first = Chat::open(TEST, &live, &ws, &[]);
    first.initialize();
    let fetched = live_audit(&live, audit_event::CODEOUT_FETCH).len();
    let told = first.turn(&format!("Remember this word for later: {word}. Then run exactly this command with your Bash tool: printf 'edited before the close\\n' >> README.md. Reply with exactly OK"));
    assert_eq!(told.result["is_error"], false, "{TEST}: {}", told.result);
    first.wait_for("the turn's codeout_fetch row", LIVE_SYNC_LIMIT, Asks::AllowAll, || (live_audit(&live, audit_event::CODEOUT_FETCH).len() > fetched).then_some(()));
    let (code, close) = first.close();
    let row = assert_closed_well(TEST, &live, &first, code, close);
    let (vm1, session) = (note_part(&row, census_part::VM).expect("the chat's VM"), first.session.clone().expect("the chat's session id"));
    let wall = vm_rows::read_row(&live.paths, &vm1).unwrap().and_then(|r| r.wall_deadline).unwrap_or_else(|| panic!("{TEST}: {vm1}'s row names no wall"));
    let inside = margin.saturating_sub(INSIDE_S);
    sleep_until_unix(TEST, &format!("{vm1} to come within {inside} s of its wall"), wall.saturating_sub(inside));
    let left = wall.saturating_sub(unix_now());
    assert!(left > INSIDE_S / 2 && left < margin, "{TEST}: {left} s of {vm1}'s wall left at the reopen: near it, not past it");
    let resume = format!("--resume={session}");
    let mut second = Chat::open(TEST, &live, &ws, &[&resume]);
    second.initialize();
    let look = second.turn("Which word did I ask you to remember? Then run exactly this command with your Bash tool: tail -n 1 README.md. Reply with the word and that line.");
    let answer = look.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer on the new VM {answer:?} lacks the word");
    assert!(look.tool_output.contains("edited before the close"), "{TEST}: the last turn's WIP came along: {}", look.tool_output);
    // The carry ends the old VM in the wrapper's background after its Started, as phase B does: the chat stays open until it has.
    let old = second.wait_for(&format!("{vm1} terminated after the carry"), LIVE_OLD_VM_LIMIT, Asks::AllowAll, || vm_rows::read_row(&live.paths, &vm1).ok().flatten().filter(|r| r.status == RowStatus::Terminated));
    assert_eq!(old.terminated_by.as_deref(), Some("migrate"), "{TEST}: the old VM's row");
    let (code, close) = second.close();
    let row = assert_closed_well(TEST, &live, &second, code, close);
    let vm2 = note_part(&row, census_part::VM).expect("the reopen's VM");
    assert_ne!(vm2, vm1, "{TEST}: the reopen carried the chat to a new VM");
    assert_eq!((note_part(&row, census_part::CARRIED).as_deref(), row_moves(&row)), (Some("migrate"), Some([0, 0, 1])), "{TEST}: the carry in the census");
    let (start, _) = moved_rows(TEST, &live, second.pid(), &session, "migrate", ("trigger", "reopen"), (&vm1, &vm2));
    assert_eq!(start["detail"]["gen"].as_str(), Some("1"), "{TEST}: the carry is the reopen's generation 1");
    let entries = vm_entries(TEST, &live, &session);
    assert!(entries.iter().any(|e| e.vm == vm2 && e.why == "migrate:reopen"), "{TEST}: the row's vms[]: {entries:?}");
    wait_for(TEST, &format!("{vm1} TERMINATED on the platform"), LIVE_OLD_VM_LIMIT, || (platform.state(&vm1) == VmState::Terminated.as_str()).then_some(()));
    let (a, b) = (first.output(), second.output());
    sweep_live(&live, &[&a, &b], &[]);
}

/// T10.4 (b) live, SLOW, as the plan has it: a reopen after the wall
/// re-addresses the chat first, and the platform's wall is recorded. In
/// [`wrapper_world`]'s 900 s wall, a chat told a word appends to README.md in
/// the VM (uncommitted; its code-out fetch records it) and closes, well
/// before the migration's margin (the plan's minute 8: the closing suspend
/// leaves the VM SUSPENDED either way). GetMicrovm follows the VM across its
/// wall: each new state is said with its `stateReason` and end time (the
/// platform's wall semantics, which `api::FAKE_WALL_REASON` only stands in
/// for), and the VM must end there (TERMINATED, or unknown to the platform).
/// A minute past the wall (the plan's minute 16) the chat reopens
/// (`--resume`): P0 to P4 re-address it to a new VM (`carried:readdress` and
/// `moves:readdress=1,respawn=0,migrate=0` in the census; `session_move`
/// `readdress`, `vm_gone`, generation 1; `session_move_end` `done`, its seed
/// `box`: the dead VM's fetch record, L7; `vms[]` `readdress:vm_gone`), and
/// the turn on the new VM recalls the word and finds the edit: the last
/// turn's WIP. The reopen's `transcript_pull` rows are said beside the Mac's
/// manifest of before: a part more than the manifest held may be a tail the
/// VM pushed at a `/terminate` the wall posted. Four Touch IDs: two chats, the
/// test process's runtime key, the purge. About seventeen minutes.
#[test]
#[ignore = "live, S10, a reopen after the wall re-addressed to a new MicroVM, the platform's wall recorded (about seventeen minutes; four Touch IDs: two chats, the test process's runtime key, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S10_TESTS=1 AI_ENV_AWS_SLOW=1 make test-aws S10=1 SLOW=1"]
fn live_s10_reopen_after_wall() {
    const TEST: &str = "live_s10_reopen_after_wall";
    // GetMicrovm from this long before the wall, so that the state before it is said too.
    const BEFORE_S: u64 = 30;
    // The reopen this long past the wall: the plan's minute 16 of a 15-minute wall.
    const PAST_S: u64 = 60;
    if !s10_slow_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = wrapper_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let platform = PlatformView::new(&live);
    let ws = s8_fixture(&live, "live-s10-reopen-after-wall");
    let word = live_word("quarry");
    let mut first = Chat::open(TEST, &live, &ws, &[]);
    first.initialize();
    let fetched = live_audit(&live, audit_event::CODEOUT_FETCH).len();
    let told = first.turn(&format!("Remember this word for later: {word}. Then run exactly this command with your Bash tool: printf 'edited before the close\\n' >> README.md. Reply with exactly OK"));
    assert_eq!(told.result["is_error"], false, "{TEST}: {}", told.result);
    first.wait_for("the turn's codeout_fetch row", LIVE_SYNC_LIMIT, Asks::AllowAll, || (live_audit(&live, audit_event::CODEOUT_FETCH).len() > fetched).then_some(()));
    let (code, close) = first.close();
    let row = assert_closed_well(TEST, &live, &first, code, close);
    let (vm1, session) = (note_part(&row, census_part::VM).expect("the chat's VM"), first.session.clone().expect("the chat's session id"));
    let wall = vm_rows::read_row(&live.paths, &vm1).unwrap().and_then(|r| r.wall_deadline).unwrap_or_else(|| panic!("{TEST}: {vm1}'s row names no wall"));
    sleep_until_unix(TEST, &format!("{BEFORE_S} s before {vm1}'s wall"), wall.saturating_sub(BEFORE_S));
    // The platform across the wall: each new look said, until it ended the VM.
    let from_wall = |now: u64| if now >= wall { format!("+{} s", now - wall) } else { format!("-{} s", wall - now) };
    let mut seen: Vec<String> = Vec::new();
    let t = Instant::now();
    let ended = loop {
        assert_eq!(CRED_SIGNAL.load(Ordering::SeqCst), 0, "{TEST}: interrupted while following {vm1} across its wall");
        let look = platform.info(&vm1);
        let said = match &look {
            Ok(Some(info)) => format!("{} (reason {:?}, terminated at {:?})", info.state.as_str(), info.state_reason, info.terminated_at_unix),
            Ok(None) => "not found".to_string(),
            Err(e) => format!("unknown: {e}"),
        };
        if seen.last() != Some(&said) {
            eprintln!("{TEST}: {vm1} at its wall {}: {said}", from_wall(unix_now()));
            seen.push(said);
        }
        match look {
            Ok(Some(info)) if info.state == VmState::Terminated => break true,
            Ok(None) => break true,
            _ if t.elapsed() >= Duration::from_secs(BEFORE_S) + LIVE_OLD_VM_LIMIT => break false,
            _ => std::thread::sleep(LIVE_SYNC_POLL),
        }
    };
    eprintln!("{TEST}: {vm1} across its wall: {}", seen.join(" > "));
    assert!(ended, "{TEST}: the platform did not end {vm1} within {LIVE_OLD_VM_LIMIT:?} of its wall: {seen:?}");
    let parts_before = ai_env_cli::bridge::s3::manifest::read(&live.paths, &session).ok().flatten().map(|m| {
        eprintln!("{TEST}: the Mac's manifest before the reopen: {} part(s), {} bytes, from {:?} at {}", m.parts.len(), m.committed, m.vm, m.at);
        m.parts.len()
    });
    sleep_until_unix(TEST, &format!("{PAST_S} s past {vm1}'s wall"), wall.saturating_add(PAST_S));
    let resume = format!("--resume={session}");
    let mut second = Chat::open(TEST, &live, &ws, &[&resume]);
    second.initialize();
    let look = second.turn("Which word did I ask you to remember? Then run exactly this command with your Bash tool: tail -n 1 README.md. Reply with the word and that line.");
    let answer = look.result["result"].as_str().unwrap_or_default().to_string();
    assert!(answer.contains(&word), "{TEST}: the answer on the new VM {answer:?} lacks the word");
    assert!(look.tool_output.contains("edited before the close"), "{TEST}: the last turn's WIP came along: {}", look.tool_output);
    let (code, close) = second.close();
    let row = assert_closed_well(TEST, &live, &second, code, close);
    let vm2 = note_part(&row, census_part::VM).expect("the reopen's VM");
    assert_ne!(vm2, vm1, "{TEST}: the reopen re-addressed the chat to a new VM");
    assert_eq!((note_part(&row, census_part::CARRIED).as_deref(), row_moves(&row)), (Some("readdress"), Some([1, 0, 0])), "{TEST}: the carry in the census");
    let (start, end) = moved_rows(TEST, &live, second.pid(), &session, "readdress", ("cause", "vm_gone"), (&vm1, &vm2));
    assert_eq!((start["detail"]["gen"].as_str(), end["detail"]["seed"].as_str()), (Some("1"), Some("box")), "{TEST}: the carry is the reopen's generation 1, seeded from the dead VM's fetch record (L7)");
    let entries = vm_entries(TEST, &live, &session);
    assert!(entries.iter().any(|e| e.vm == vm2 && e.why == "readdress:vm_gone"), "{TEST}: the row's vms[]: {entries:?}");
    let pulls: Vec<serde_json::Value> = live_audit(&live, audit_event::TRANSCRIPT_PULL).into_iter().filter(|r| r["detail"]["session"] == session.as_str() && r["detail"]["vm"] == vm2.as_str()).map(|r| r["detail"].clone()).collect();
    eprintln!("{TEST}: the reopen's transcript_pull rows into {vm2} (the Mac's manifest held {parts_before:?} part(s) before it; a part more may be a tail the VM pushed at a /terminate the wall posted): {pulls:?}");
    let (a, b) = (first.output(), second.output());
    sweep_live(&live, &[&a, &b], &[]);
}

// ---- S11: claude always fresh and S10's leftovers, live (part B: B3 (e) and B4 (a), `make test-aws S11=1`) ----
//
// S11 wave 2 (L). Chats of the real `ai-env-claude` in remote mode on S8's
// rig (`wrapper_world`, `Chat`; the setup-token sealed) against image 13.0,
// each in a fixture under this checkout's `target/s8/` (never the
// development chat), in S10's kind of world with `[claude] auto_admit =
// false` (`s11_world`: no wall and no migration inside a test, and no
// automatic admission started in a test's root). Part A: an option the VM's
// claude does not know, dropped by a same-VM respawn
// (`live_s11_unknown_option_respawns`, B3 (e)); the installed Cursor bundle's
// claude admitted in the test's root, staged through a stager VM and fetched
// ahead by `vm warm` (`live_s11_stager_stages_the_bundle`); a cold VM's chat
// on the image's claude fetching the bundle's after its first output, and the
// next chat there running it cached (`live_s11_claude_src_cached_after_fetch`,
// on this Mac's admitted and staged record of it). Part C: F1, a `git
// checkout -b` carried across a re-address
// (`live_s11_checkout_b_then_readdress`); C-4, a move mid-turn after
// `/compact` (`live_s11_compact_then_move`); and what the CLI writes into a
// fork's file, against the fake's FK-3 (`live_s11_fork_first_write`, a
// measurement). Each Touch ID is announced as S10's are
// (`announce_touch_id`); each test's count includes the test process's
// runtime key, as when it runs alone, and one for its chats' S3 objects
// (`PurgeTranscripts`; none for a test without a chat). No S11 test reads
// AI_ENV_AWS_SLOW or the code token's minutes.

use ai_env_cli::bridge::claude::{Phase as ClaudePhase, Record as ClaudeRecord};

/// Whether S11's live tests run: [`live`], and AI_ENV_S11_TESTS=1 (`make test-aws S11=1`).
fn s11_live() -> bool {
    if !live() {
        return false;
    }
    if std::env::var("AI_ENV_S11_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set AI_ENV_S11_TESTS=1 too (make test-aws S11=1) for S11's chats");
    false
}

/// [`s10_world`] (no wall and no migration inside a test, then `vm`'s keys)
/// with `[claude] auto_admit = false` in the temporary root's bridge.toml: no
/// chat of a test starts an automatic admission there (D5; the runbook's
/// Found 4). Part A's tests hold the record they need, or make it with
/// `ai-env claude admit`, which the switch never stops.
fn s11_world(vm: &[(&str, toml::Value)]) -> Live {
    let mut live = s10_world(vm);
    let mut doc: toml::Table = toml::from_str(&std::fs::read_to_string(&live.paths.config).unwrap()).expect("the copied bridge.toml");
    let table = doc.entry("claude").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    table.as_table_mut().expect("[claude] is a table").insert("auto_admit".into(), toml::Value::Boolean(false));
    std::fs::write(&live.paths.config, toml::to_string(&doc).unwrap()).unwrap();
    live.cfg = BridgeConfig::load(&live.paths).unwrap().expect("bridge.toml");
    assert!(!live.cfg.claude.auto_admit, "the test's root admits nothing by itself");
    live
}

/// argv[1] of a chat of the Cursor bundle `version`, under `root`:
/// `<root>/extensions/anthropic.claude-code-<version>-darwin-arm64/resources/native-binary/claude`,
/// whose bundle the census reads as the chat's `ext` (P0's V). No file is
/// there: in remote mode no Mac binary runs, and a local run of it fails at
/// once.
fn bundle_argv1(root: &std::path::Path, version: &str) -> std::path::PathBuf {
    root.join("extensions").join(format!("anthropic.claude-code-{version}-darwin-arm64")).join("resources").join("native-binary").join("claude")
}

/// The installed Cursor bundle's Claude Code version (`claude::installed_bundle`:
/// `~/.cursor/extensions`' names, as `ai-env infra pin --bundle-version`
/// reads them): V, which part A's tests admit, stage and fetch.
fn s11_bundle_version(test: &str) -> String {
    let v = ai_env_cli::bridge::claude::installed_bundle().unwrap_or_else(|| panic!("{test}: no installed Cursor bundle names a claude version (~/.cursor/extensions)"));
    eprintln!("{test}: the installed Cursor bundle's claude: {v}");
    v
}

/// This Mac's record of claude `version` (`state/claude/<v>.toml` of the real
/// bridge root) written into the test's root (`Record::update`), so that a
/// chat of that bundle names it to its VM. Part B's B3 (a) and (b) admitted
/// and staged it: any other phase fails the test naming them.
fn adopt_claude_record(test: &str, live: &Live, version: &str) {
    let real = Paths::resolve().expect("the real bridge root");
    let record = ClaudeRecord::load(&real, version)
        .unwrap_or_else(|e| panic!("{test}: this Mac's record of claude {version}: {e}"))
        .unwrap_or_else(|| panic!("{test}: this Mac has no record of claude {version}: ai-env claude admit {version}, then ai-env claude stage {version} (part B's B3 (a) and (b))"));
    assert_eq!(record.phase(), ClaudePhase::Staged, "{test}: claude {version} is {} on this Mac: ai-env claude stage {version} (part B's B3 (b)) stages it", record.phase().word());
    let adopted = ClaudeRecord::update(&live.paths, version, |r| *r = record.clone()).unwrap_or_else(|e| panic!("{test}: claude {version}'s record into the test's root: {e}"));
    let staging = adopted.staging.unwrap_or_default();
    eprintln!("{test}: claude {version} staged at {} since {} (this Mac's record)", staging.s3_key, staging.at);
}

/// The lines of `session`'s view on the Mac as they are now, none while its
/// row names no view or the file cannot be read (a poll's probe;
/// [`assert_a_view`] judges the file).
fn view_lines_now(live: &Live, session: &str) -> Vec<String> {
    let Some(view) = ai_env_cli::bridge::registry::read(&live.paths, session).ok().flatten().and_then(|r| r.view) else { return Vec::new() };
    std::fs::read_to_string(mac_projects().join(view)).map(|t| t.lines().map(str::to_string).collect()).unwrap_or_default()
}

/// How many of a view's `lines` are a user's prompt holding `marker` (C-4:
/// the nonce's): a `user` line whose content is text (a string, or text
/// blocks) holding it. The assistant's call and the tool's result that hold
/// it too never count.
fn prompt_lines(lines: &[String], marker: &str) -> usize {
    lines
        .iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "user")
        .filter(|v| match &v["message"]["content"] {
            serde_json::Value::String(s) => s.contains(marker),
            serde_json::Value::Array(blocks) => blocks.iter().any(|b| b["type"] == "text" && b["text"].as_str().is_some_and(|t| t.contains(marker))),
            _ => false,
        })
        .count()
}

/// One JSONL file's shape as [`fork_shape_script`] prints it: whether it
/// exists, and each line's type and uuid (`None`: none), in order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FileShape {
    present: bool,
    lines: Vec<(String, Option<String>)>,
}

impl FileShape {
    /// The uuids of its `user` and `assistant` lines, in order.
    fn messages(&self) -> Vec<&str> {
        self.lines.iter().filter(|(t, _)| t == "user" || t == "assistant").filter_map(|(_, u)| u.as_deref()).collect()
    }
}

/// The `sh -c` script `vm exec` runs for the fork's shape (C §C.6.3, small
/// item f), shell builtins alone (the image has no jq): for the files
/// `<x>.jsonl` (tag `x`) and `<f>.jsonl` (tag `f`) under
/// `$HOME/.claude/projects/<slug>/`, `<tag>_file=present` (or `absent`), one
/// line `<tag> <n> <type> <uuid>` per JSONL line, then `<tag>_lines=<n>`. The
/// type is the line's own: `user`, `assistant`, `system` or `summary` by its
/// `"type":"…"` pair (an assistant line's message carries a type of its own
/// first; a JSON string's quotes are escaped, so a quoted type never
/// matches), else the first such pair's word; the uuid is the first
/// `"uuid":"…"` pair's (a message has none of its own). Each is printed only
/// when it is a plain word (lowercase letters, `_` and `-`; hex digits and
/// `-`), else `?` and `-`: uuids and types, never content.
fn fork_shape_script(slug: &str, x: &str, f: &str) -> String {
    for (what, word) in [("slug", slug), ("x", x), ("f", f)] {
        assert!(!word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "the fork's shape script: its {what} is no plain word: {word:?}");
    }
    let body = r#"d="$HOME/.claude/projects/@SLUG@"
kind() {
  case "$1" in
    *'"type":"user"'*) k=user ;;
    *'"type":"assistant"'*) k=assistant ;;
    *'"type":"system"'*) k=system ;;
    *'"type":"summary"'*) k=summary ;;
    *) r=${1#*'"type":"'}
       if [ "$r" = "$1" ]; then k='?'; else k=${r%%'"'*}; fi
       case "$k" in ''|*[!a-z_-]*) k='?' ;; esac ;;
  esac
}
uid() {
  r=${1#*'"uuid":"'}
  if [ "$r" = "$1" ]; then u=-; else u=${r%%'"'*}; fi
  case "$u" in ''|*[!0-9a-f-]*) u=- ;; esac
}
shape() {
  if [ ! -f "$2" ]; then echo "$1_file=absent"; return; fi
  echo "$1_file=present"
  n=0
  while IFS= read -r l || [ -n "$l" ]; do
    n=$((n + 1)); kind "$l"; uid "$l"; echo "$1 $n $k $u"
  done < "$2"
  echo "$1_lines=$n"
}
shape x "$d/@X@.jsonl"
shape f "$d/@F@.jsonl"
"#;
    body.replace("@SLUG@", slug).replace("@X@", x).replace("@F@", f)
}

/// X's and F's shapes from [`fork_shape_script`]'s output; `None` when its
/// lines do not add up (an unknown line, a line out of its order, a count
/// that is not its lines').
fn fork_shapes(out: &str) -> Option<(FileShape, FileShape)> {
    let slot = |tag: &str| match tag {
        "x" => Some(0usize),
        "f" => Some(1usize),
        _ => None,
    };
    let mut shapes = [FileShape::default(), FileShape::default()];
    let mut counted = [0usize; 2];
    for line in out.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let (tag, what) = key.split_once('_')?;
            let i = slot(tag)?;
            match (what, value) {
                ("file", "present") => shapes[i].present = true,
                ("file", "absent") => shapes[i].present = false,
                ("lines", n) => counted[i] = n.parse().ok()?,
                _ => return None,
            }
            continue;
        }
        let words: Vec<&str> = line.split(' ').collect();
        let [tag, n, kind, uuid] = words.as_slice() else { return None };
        let i = slot(tag)?;
        if n.parse::<usize>().ok()? != shapes[i].lines.len() + 1 {
            return None;
        }
        shapes[i].lines.push(((*kind).to_string(), (*uuid != "-").then(|| (*uuid).to_string())));
    }
    let [x, f] = shapes;
    (counted == [x.lines.len(), f.lines.len()]).then_some((x, f))
}

/// FK-3 (S10 §8.4, `plans/s10-contracts.md`): the fake's fork copies X's user
/// and assistant lines into F's file at its first write. `Ok` when F's file
/// shows that (all of X's user and assistant uuids, in X's order, are F's
/// first user and assistant lines), else what differs.
fn fk3_verdict(x: &FileShape, f: &FileShape) -> Result<(), String> {
    let (xs, fs) = (x.messages(), f.messages());
    if !xs.is_empty() && fs.starts_with(&xs) {
        return Ok(());
    }
    let found = xs.iter().filter(|u| fs.contains(u)).count();
    let lead: Vec<&str> = fs.iter().take(xs.len().max(1)).copied().collect();
    Err(format!("{found} of X's {} user and assistant uuids are in F's file; F's first user and assistant uuids {lead:?}, X's {xs:?}", xs.len()))
}

/// F's own user and assistant lines (each with a uuid none of X's): how many of each.
fn own_messages(x: &FileShape, f: &FileShape) -> (usize, usize) {
    let xs = x.messages();
    let own = |kind: &str| f.lines.iter().filter(|(t, u)| t == kind && u.as_deref().is_some_and(|u| !xs.contains(&u))).count();
    (own("user"), own("assistant"))
}

/// Offline (S11): a bundled chat's argv[1] names its bundle's version as the
/// census reads it (the chat's `ext`), under the temporary root.
#[test]
fn a_bundled_chats_argv1_names_its_version() {
    let p = bundle_argv1(std::path::Path::new("/tmp/live-root"), "2.1.308");
    assert!(p.starts_with("/tmp/live-root"), "{}", p.display());
    let os = p.into_os_string();
    assert_eq!(ai_env_cli::bridge::census::ext_version_from_real_binary(Some(&os)).as_deref(), Some("2.1.308"));
}

/// Offline (S11, C-4): [`prompt_lines`] counts a view's prompts holding a
/// marker, as a string or as text blocks, and never the assistant's call or
/// the tool's result that hold it too.
#[test]
fn a_views_prompt_is_counted_apart_from_its_call_and_result() {
    let marker = "slept-ab12";
    let lines: Vec<String> = [
        serde_json::json!({"type": "user", "message": {"role": "user", "content": format!("run this: sleep 90; echo {marker}")}}),
        serde_json::json!({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": format!("sleep 90; echo {marker}")}}]}}),
        serde_json::json!({"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": marker}]}}),
        serde_json::json!({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": marker}]}}),
        serde_json::json!({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": format!("again: {marker}")}]}}),
        serde_json::json!({"type": "user", "message": {"role": "user", "content": "Reply with exactly OK"}}),
    ]
    .iter()
    .map(ToString::to_string)
    .chain(std::iter::once("not json".to_string()))
    .collect();
    assert_eq!(prompt_lines(&lines, marker), 2);
    assert_eq!(prompt_lines(&lines[..1], marker), 1);
    assert_eq!(prompt_lines(&lines, "absent"), 0);
}

/// Offline (S11, the fork's shape): [`fork_shape_script`] under this Mac's
/// `/bin/sh`, on files of the forms claude writes (an assistant line whose
/// message carries its own type, a tool's result whose text quotes a type, a
/// summary with no uuid of its own, a snapshot, a last line without its
/// newline), prints each line's type and uuid and no content; a missing file
/// is absent. [`fork_shapes`] reads it back (and refuses lines that do not
/// add up); [`fk3_verdict`] and [`own_messages`] judge it.
#[test]
fn the_fork_shape_is_types_and_uuids_only() {
    const WORD: &str = "contentwordnevershown";
    let home = tempfile::tempdir().unwrap();
    let slug = "-tmp-live-s11-fork";
    let (x, f) = ("0199a1b2-0000-7000-8000-00000000000a", "0199a1b2-0000-7000-8000-00000000000f");
    let dir = home.path().join(".claude").join("projects").join(slug);
    std::fs::create_dir_all(&dir).unwrap();
    let u = |n: u32| format!("0199a1b2-0000-7000-8000-{n:012x}");
    let user = |id: &str, content: serde_json::Value| serde_json::json!({"parentUuid": null, "isSidechain": false, "type": "user", "message": {"role": "user", "content": content}, "uuid": id, "timestamp": "2026-10-23T08:00:00Z"}).to_string();
    let assistant = |id: &str| {
        serde_json::json!({"parentUuid": null, "isSidechain": false, "message": {"id": "msg_1", "type": "message", "role": "assistant", "content": [{"type": "text", "text": WORD}]}, "requestId": "req_1", "type": "assistant", "uuid": id, "timestamp": "2026-10-23T08:00:01Z"}).to_string()
    };
    let summary = serde_json::json!({"type": "summary", "summary": WORD, "leafUuid": u(2)}).to_string();
    let snapshot = serde_json::json!({"type": "file-history-snapshot", "messageId": u(9), "snapshot": {"files": [WORD]}}).to_string();
    let quoted = user(&u(5), serde_json::json!([{"type": "tool_result", "tool_use_id": "t1", "content": format!("{WORD} \"type\":\"assistant\" \"uuid\":\"{}\"", u(7))}]));
    let x_lines = [user(&u(1), serde_json::json!(format!("Reply {WORD}"))), assistant(&u(2)), summary];
    std::fs::write(dir.join(format!("{x}.jsonl")), format!("{}\n", x_lines.join("\n"))).unwrap();
    let f_lines = [user(&u(1), serde_json::json!(format!("Reply {WORD}"))), assistant(&u(2)), snapshot, user(&u(3), serde_json::json!(WORD)), assistant(&u(4)), quoted];
    // The last line without its newline.
    std::fs::write(dir.join(format!("{f}.jsonl")), f_lines.join("\n")).unwrap();
    let run = |script: &str| {
        let out = std::process::Command::new("/bin/sh").arg("-c").arg(script).env_clear().env("HOME", home.path()).env("PATH", "/usr/bin:/bin").output().expect("/bin/sh");
        assert!(out.status.success(), "the script: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("UTF-8")
    };
    let out = run(&fork_shape_script(slug, x, f));
    assert!(!out.contains(WORD) && !out.contains("Reply"), "no content: {out}");
    let (xs, fs) = fork_shapes(&out).unwrap_or_else(|| panic!("the shape lines add up: {out}"));
    let shape = |lines: &[(&str, Option<u32>)]| FileShape { present: true, lines: lines.iter().map(|(t, n)| ((*t).to_string(), n.map(u))).collect() };
    assert_eq!(xs, shape(&[("user", Some(1)), ("assistant", Some(2)), ("summary", None)]), "{out}");
    assert_eq!(fs, shape(&[("user", Some(1)), ("assistant", Some(2)), ("file-history-snapshot", None), ("user", Some(3)), ("assistant", Some(4)), ("user", Some(5))]), "{out}");
    assert_eq!(fk3_verdict(&xs, &fs), Ok(()));
    assert_eq!(own_messages(&xs, &fs), (2, 1));
    // F without X's lines: what differs is said; F's own turn is still there.
    let bare = FileShape { present: true, lines: fs.lines[3..].to_vec() };
    let differs = fk3_verdict(&xs, &bare).expect_err("no copy of X's lines");
    assert!(differs.starts_with("0 of X's 2 user and assistant uuids are in F's file"), "{differs}");
    assert_eq!(own_messages(&xs, &bare), (2, 1));
    // A file that is not there is absent.
    let (_, gone) = fork_shapes(&run(&fork_shape_script(slug, x, "0199a1b2-0000-7000-8000-0000000000ff"))).expect("absent adds up");
    assert_eq!(gone, FileShape::default());
    for bad in ["x 2 user -", "x 1 user", "y 1 user -", "x_lines=2", "x_file=maybe", "x 1 user - extra"] {
        assert_eq!(fork_shapes(bad), None, "{bad}");
    }
}

/// T11 live, plan B3 (e) (A.5, L1): an option the VM's claude does not know
/// costs a chat nothing. The real `ai-env-claude` starts with
/// `--ai-env-s11-probe` after the extension's argv; claude refuses it before
/// `initialize` (`error: unknown option '--ai-env-s11-probe'`), and the
/// wrapper starts it again on the same VM without it and without a Touch ID
/// (`session_remote_start` of generation 2, `why` `argv_retry`, on generation
/// 1's VM): `initialize` is answered (its time printed against Cursor's 60 s,
/// the respawn inside it) and a turn answers; the end row says
/// `argv_dropped:--ai-env-s11-probe` and exit 0, and the audit holds one
/// `argv_dropped` row of the flag (once per flag and claude version). Three
/// Touch IDs: the chat, the test process's runtime key, the purge. About
/// three minutes.
#[test]
#[ignore = "live, S11 part A, an unknown option dropped by a same-VM respawn (about three minutes; three Touch IDs: the chat, the test process's runtime key, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S11_TESTS=1 make test-aws S11=1"]
fn live_s11_unknown_option_respawns() {
    const TEST: &str = "live_s11_unknown_option_respawns";
    const PROBE: &str = "--ai-env-s11-probe";
    if !s11_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s11_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s11-unknown-option");
    let mut chat = Chat::open(TEST, &live, &ws, &[PROBE]);
    // Cursor's window with the respawn inside it: said, not judged (the contract judges the drop and the exit).
    let init = chat.initialize_within(LIVE_INIT_LIMIT * 2);
    eprintln!("{TEST}: initialize answered after {} ms, the respawn inside it (Cursor waits {} s)", init.as_millis(), LIVE_INIT_LIMIT.as_secs());
    let turn = chat.turn("Reply with exactly OK");
    assert_eq!(turn.result["is_error"], false, "{TEST}: the turn on the respawned claude: {}", turn.result);
    let pid = chat.pid();
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    eprintln!(
        "{TEST}: claude:{:?} claude_src:{:?} argv_dropped:{:?}",
        note_part(&row, census_part::CLAUDE),
        note_part(&row, census_part::CLAUDE_SRC),
        note_part(&row, census_part::ARGV_DROPPED)
    );
    assert_eq!(note_part(&row, census_part::ARGV_DROPPED).as_deref(), Some(PROBE), "{TEST}: the end row names the dropped option");
    let starts = audit_of(&live, audit_event::SESSION_REMOTE_START, pid);
    eprintln!("{TEST}: session_remote_start {:?}", starts.iter().map(|r| r["detail"].clone()).collect::<Vec<_>>());
    let gen = |n: &str| starts.iter().find(|r| r["detail"]["gen"] == n).map(|r| (r["detail"]["why"].as_str().unwrap_or_default().to_string(), r["detail"]["id"].as_str().unwrap_or_default().to_string()));
    let (Some((why1, vm1)), Some((why2, vm2))) = (gen("1"), gen("2")) else { panic!("{TEST}: generations 1 and 2 started: {starts:?}") };
    assert_eq!((why1.as_str(), why2.as_str()), ("first", "argv_retry"), "{TEST}: generation 2 is the start-up respawn");
    assert_eq!(vm2, vm1, "{TEST}: the respawn stayed on generation 1's VM");
    let dropped = audit_of(&live, audit_event::ARGV_DROPPED, pid);
    let [one] = dropped.as_slice() else { panic!("{TEST}: one argv_dropped row: {dropped:?}") };
    eprintln!("{TEST}: argv_dropped {}", one["detail"]);
    assert_eq!(one["detail"]["flag"].as_str(), Some(PROBE), "{TEST}: {one}");
    let refused = chat.stderr_now().contains(&format!("unknown option '{PROBE}'"));
    eprintln!("{TEST}: claude's refusal of {PROBE} in the wrapper's stderr: {refused}");
    let out = chat.output();
    sweep_live(&live, &[&out], &[]);
}

/// T11 live, plan B3 (a), (b) and (d) in a test's root (D1, D2, D3): the
/// installed Cursor bundle's claude V is admitted there (`ai-env claude admit
/// V --json`, no Touch ID: the release's signature by the pinned key, the
/// binary's size and sha256, its markers, then the Docker tests on the local
/// image, so Docker must answer), then staged through a stager VM (`ai-env
/// claude stage V --force --json`, one Touch ID). `--force` deletes the
/// object S3 holds first: part B's B3 (b) staged V already, and without it
/// the Mac's listing would answer `already_staged` with no VM. The stager is a
/// credential-less internet VM (`vm_run` `purpose` `claude-stage`) that relays
/// the signed release into the presigned PUT, then ends (`vm_terminate` `by`
/// `claude-stage`, its row `terminated_by` too): `staged` (S3's 200), or
/// `exists` (412: counted as staged, unverified) when the object came back
/// meanwhile; the record says `staged` at `v1/_claude/mac/<V>/<sha256>`
/// through that VM. Then `vm warm` of a fresh fixture fetches V ahead into the
/// workspace's new VM (`fetched`, a `claude_fetch` row `why` `warm`;
/// `fetching` past its 120 s is said), and a second warm finds it `cached`
/// there. The admission's and the stage's times are printed. Four Touch IDs:
/// the test process's runtime key, the stage, two `vm warm`. About ten
/// minutes, the Docker tests most of them.
#[test]
#[ignore = "live, S11 part A, the installed bundle's claude admitted in the test's root (Docker running), staged through a stager MicroVM, then fetched ahead by vm warm (about ten minutes; four Touch IDs: the test process's runtime key, the stage, two vm warm): AI_ENV_AWS_TESTS=1 AI_ENV_S11_TESTS=1 make test-aws S11=1"]
fn live_s11_stager_stages_the_bundle() {
    const TEST: &str = "live_s11_stager_stages_the_bundle";
    // A warm: the VM, the seed, the delivery, then the fetch's wait (`WARM_CLAUDE_WAIT`).
    const WARM_LIMIT: Duration = Duration::from_secs(600);
    if !s11_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s11_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let v = s11_bundle_version(TEST);
    // D2: the admission in the test's root: the release's download, then the Docker tests (`ADMIT_MAKE_BOUND`).
    let t = Instant::now();
    let admitted = ai_env_live_within(&live, &["claude", "admit", &v, "--json"], ai_env_cli::bridge::claude::ADMIT_MAKE_BOUND + Duration::from_secs(600));
    let admit_ms = t.elapsed().as_millis();
    let doc: serde_json::Value = serde_json::from_slice(&admitted.stdout).unwrap_or_else(|e| panic!("{TEST}: claude admit {v} --json ({e}): {}", String::from_utf8_lossy(&admitted.stdout)));
    eprintln!("{TEST}: claude admit {v} took {admit_ms} ms: {doc}");
    assert_eq!(admitted.status.code(), Some(0), "{TEST}: claude admit {v} (Docker must answer: its tests run on {v}): {doc}");
    assert_eq!(
        (doc["outcome"].as_str(), doc["phase"].as_str(), doc["signer"].as_str(), doc["markers"].as_str()),
        (Some("admitted"), Some("admitted"), Some(ai_env_cli::wire::pin::RELEASE_KEY_FPR), Some("ok")),
        "{TEST}: signed by the release key, its markers there, its Docker tests passed: {doc}"
    );
    let sha = doc["sha256"].as_str().unwrap_or_else(|| panic!("{TEST}: the admitted binary's sha256: {doc}")).to_string();
    let admits = live_audit(&live, audit_event::CLAUDE_ADMIT);
    assert!(admits.iter().any(|r| r["detail"]["version"] == v.as_str() && r["detail"]["outcome"] == "admitted"), "{TEST}: the claude_admit row: {admits:?}");
    // D1: the stage through a stager VM; --force deletes what S3 holds first.
    announce_touch_id(TEST, &format!("claude stage {v} --force: the runtime key (a stager VM relays the release into S3)"));
    let t = Instant::now();
    let staged = ai_env_live_within(&live, &["claude", "stage", &v, "--force", "--json"], Duration::from_secs(u64::from(ai_env_cli::bridge::claude::STAGER_MAX_DURATION_S)));
    let stage_ms = t.elapsed().as_millis();
    let doc: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap_or_else(|e| panic!("{TEST}: claude stage {v} --json ({e}): {}", String::from_utf8_lossy(&staged.stdout)));
    eprintln!("{TEST}: claude stage {v} --force took {stage_ms} ms: {doc}");
    assert_eq!(staged.status.code(), Some(0), "{TEST}: claude stage {v}: {doc}");
    let outcome = doc["outcome"].as_str().unwrap_or_default().to_string();
    assert!(outcome == "staged" || outcome == "exists", "{TEST}: staged (S3's 200), or exists (its 412: counted as staged): {doc}");
    let key = format!("v1/_claude/mac/{v}/{sha}");
    assert_eq!(doc["key"].as_str(), Some(key.as_str()), "{TEST}: the object's key: {doc}");
    let stager = doc["vm"].as_str().unwrap_or_else(|| panic!("{TEST}: no stager VM: {doc}")).to_string();
    let runs = live_audit(&live, "vm_run");
    let run = runs.iter().find(|r| r["detail"]["id"] == stager.as_str()).unwrap_or_else(|| panic!("{TEST}: no vm_run row of {stager}: {runs:?}"));
    assert_eq!((run["detail"]["purpose"].as_str(), run["detail"]["egress"].as_str()), (Some("claude-stage"), Some("internet")), "{TEST}: the stager's run: {}", run["detail"]);
    let ends = live_audit(&live, "vm_terminate");
    assert!(ends.iter().any(|r| r["detail"]["id"] == stager.as_str() && r["detail"]["by"] == "claude-stage"), "{TEST}: the stage ended its stager: {ends:?}");
    let row = vm_rows::read_row(&live.paths, &stager).unwrap().unwrap_or_else(|| panic!("{TEST}: no row of {stager}"));
    assert_eq!((row.status, row.terminated_by.as_deref()), (RowStatus::Terminated, Some("claude-stage")), "{TEST}: the stager's row");
    let stages: Vec<serde_json::Value> = live_audit(&live, audit_event::CLAUDE_STAGE).into_iter().map(|r| r["detail"].clone()).collect();
    eprintln!("{TEST}: claude_stage {stages:?}");
    assert!(stages.iter().any(|d| d["outcome"] == "deleted" && d["why"] == "force"), "{TEST}: --force deleted the object first: {stages:?}");
    assert!(stages.iter().any(|d| d["outcome"] == outcome.as_str() && d["vm"] == stager.as_str()), "{TEST}: the stage's row: {stages:?}");
    let record = ClaudeRecord::load(&live.paths, &v).unwrap().unwrap_or_else(|| panic!("{TEST}: no record of claude {v}"));
    let staging = record.staging.clone().unwrap_or_default();
    assert_eq!((record.phase(), staging.s3_key.as_str(), staging.stager_vm.as_deref()), (ClaudePhase::Staged, key.as_str(), Some(stager.as_str())), "{TEST}: the record");
    // D3: vm warm fetches V ahead into a fresh workspace's VM; a second warm finds it cached there.
    let ws = s8_fixture(&live, "live-s11-stager-warm");
    let w = ws.display().to_string();
    let warm = |n: u32| -> (serde_json::Value, std::process::Output) {
        announce_touch_id(TEST, &format!("vm warm {w} ({n} of 2): the runtime key and the setup-token"));
        let out = ai_env_live_within(&live, &["vm", "warm", &w, "--claude-version", &v, "--json"], WARM_LIMIT);
        assert_eq!(out.status.code(), Some(0), "{TEST}: vm warm ({n} of 2): {}", String::from_utf8_lossy(&out.stdout));
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{TEST}: vm warm --json ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        eprintln!("{TEST}: vm warm ({n} of 2): {doc}");
        (doc, out)
    };
    let (first, warmed) = warm(1);
    let vm = first["id"].as_str().unwrap_or_else(|| panic!("{TEST}: no id in {first}")).to_string();
    announce_holder(TEST, &vm);
    let fetched = first["claude"]["outcome"].as_str().unwrap_or_default().to_string();
    assert_eq!((first["reused"].as_bool(), first["claude"]["version"].as_str()), (Some(false), Some(v.as_str())), "{TEST}: a new VM, claude {v}: {first}");
    assert!(fetched == "fetched" || fetched == "fetching", "{TEST}: the first warm fetched claude {v} into {vm} (or still fetched it after {} s): {first}", remote::WARM_CLAUDE_WAIT.as_secs());
    let (second, again) = warm(2);
    assert_eq!(
        (second["id"].as_str(), second["reused"].as_bool(), second["claude"]["outcome"].as_str()),
        (Some(vm.as_str()), Some(true), Some("cached")),
        "{TEST}: the second warm found claude {v} cached on {vm}: {second}"
    );
    let fetches: Vec<serde_json::Value> = live_audit(&live, audit_event::CLAUDE_FETCH).into_iter().map(|r| r["detail"].clone()).filter(|d| d["vm"] == vm.as_str()).collect();
    eprintln!("{TEST}: claude_fetch into {vm}: {fetches:?}");
    if fetched == "fetched" {
        assert!(fetches.iter().any(|d| d["why"] == "warm" && d["outcome"] == "fetched" && d["version"] == v.as_str()), "{TEST}: the warm's fetch row: {fetches:?}");
    } else {
        eprintln!("{TEST}: the first warm was still fetching after its {} s (part B records it)", remote::WARM_CLAUDE_WAIT.as_secs());
    }
    // The release's own binary and the Docker tests' log are not this test's output: the sweep reads the rest.
    let _ = std::fs::remove_dir_all(live.paths.claude_bin_dir(&v));
    let _ = std::fs::remove_file(live.paths.logs().join(format!("claude-admit-{v}.log")));
    sweep_live(&live, &[&admitted, &staged, &warmed, &again], &[]);
}

/// T11 live, plan B3 (c) on a cold VM (D3): a VM that lacks V runs the
/// image's claude, fetches V after the chat's first output, and the next chat
/// there runs V. The test's root holds this Mac's record of V, the installed
/// bundle's, admitted and staged by part B's B3 (a) and (b)
/// ([`adopt_claude_record`]); the chats name V's bundle
/// ([`Chat::open_bundled`]); `[claude] auto_admit = false` there, and V's
/// record is past `signed`, so P0 starts no admission. The first chat starts
/// the workspace's VM: `claude_src:image(not_cached)` (V nameable and sent,
/// the cache lacking it), its `claude:` the image's (which must not be V);
/// its first output starts V's fetch, a `claude_fetch` row (`why`
/// `after_output`, `outcome` `fetched`) while it stays open. The next chat
/// there (the VM kept running: `suspend_on_close = false`) says
/// `claude:<V>; claude_src:cached`, its `auth_timers` printed. Four Touch IDs:
/// two chats, the test process's runtime key, the purge. About five minutes.
#[test]
#[ignore = "live, S11 part A, a cold MicroVM's chat on the image's claude fetches the bundle's after its first output, and the next chat there runs it cached (about five minutes; four Touch IDs: two chats, the test process's runtime key, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S11_TESTS=1 make test-aws S11=1"]
fn live_s11_claude_src_cached_after_fetch() {
    const TEST: &str = "live_s11_claude_src_cached_after_fetch";
    if !s11_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s11_world(&[("suspend_on_close", toml::Value::Boolean(false)), ("reuse_per_workspace", toml::Value::Boolean(true))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let v = s11_bundle_version(TEST);
    adopt_claude_record(TEST, &live, &v);
    let ws = s8_fixture(&live, "live-s11-claude-src");
    let mut first = Chat::open_bundled(TEST, &live, &ws, &v, &[]);
    first.initialize();
    let turn = first.turn("Reply with exactly OK");
    assert_eq!(turn.result["is_error"], false, "{TEST}: the cold VM's chat: {}", turn.result);
    let (vm1, pid) = (first.session_vm(&live), first.pid());
    let fetch = first.wait_for(&format!("claude {v}'s fetch into {vm1} after the chat's first output"), remote::CLAUDE_POLL_FOR + Duration::from_secs(60), Asks::AllowAll, || {
        audit_of(&live, audit_event::CLAUDE_FETCH, pid).into_iter().find(|r| r["detail"]["vm"] == vm1.as_str() && r["detail"]["why"] == "after_output")
    });
    eprintln!("{TEST}: claude_fetch {}", fetch["detail"]);
    assert_eq!((fetch["detail"]["version"].as_str(), fetch["detail"]["outcome"].as_str()), (Some(v.as_str()), Some("fetched")), "{TEST}: V's fetch after the first output: {}", fetch["detail"]);
    let (code, close) = first.close();
    let cold = assert_closed_well(TEST, &live, &first, code, close);
    let (image, src) = (note_part(&cold, census_part::CLAUDE), note_part(&cold, census_part::CLAUDE_SRC));
    eprintln!("{TEST}: the cold VM's chat on {vm1}: claude:{image:?} claude_src:{src:?}");
    assert_ne!(image.as_deref(), Some(v.as_str()), "{TEST}: the image's claude is {v} already: no cold case to show");
    assert_eq!((note_part(&cold, census_part::VM).as_deref(), src.as_deref()), (Some(vm1.as_str()), Some("image(not_cached)")), "{TEST}: the cold VM ran the image's claude, {v} not cached there yet");
    let mut second = Chat::open_bundled(TEST, &live, &ws, &v, &[]);
    second.initialize();
    let again = second.turn("Reply with exactly OK");
    assert_eq!(again.result["is_error"], false, "{TEST}: the next chat: {}", again.result);
    let (code, close) = second.close();
    let cached = assert_closed_well(TEST, &live, &second, code, close);
    eprintln!(
        "{TEST}: the next chat: vm_how:{:?} claude:{:?} claude_src:{:?} auth_timers:{:?}",
        note_part(&cached, census_part::VM_HOW),
        note_part(&cached, census_part::CLAUDE),
        note_part(&cached, census_part::CLAUDE_SRC),
        note_part(&cached, census_part::AUTH_TIMERS)
    );
    assert_eq!(note_part(&cached, census_part::VM).as_deref(), Some(vm1.as_str()), "{TEST}: the next chat ran on the same VM");
    assert_eq!(
        (note_part(&cached, census_part::CLAUDE).as_deref(), note_part(&cached, census_part::CLAUDE_SRC).as_deref()),
        (Some(v.as_str()), Some("cached")),
        "{TEST}: the next chat ran {v} from the VM's cache"
    );
    let (a, b) = (first.output(), second.output());
    sweep_live(&live, &[&a, &b], &[]);
}

/// T11 live, F1 (C §C.1): a `git checkout -b` survives a re-address. Turn 1
/// runs `git checkout -b topic` (allowed if claude asks); the code-out after
/// its result is a manifest-only 200 (the VM names `codeout_manifest_v1`): its
/// `codeout_fetch` row's `bytes` 0, and the workspace row's fetch record of
/// that VM names `topic` (`rows::row_of`). `vm terminate` ends the VM with the
/// chat idle (L5's note), the next line re-addresses the chat
/// (`session_move_end` `readdress`, `done`, its seed `box`: the dead VM's
/// record, on a branch other than this Mac's `main`, is the box's), and `git
/// -C <path> branch --show-current` on the new VM (`vm exec`) prints `topic`.
/// Six Touch IDs: the chat, the test process's runtime key, the terminate, the
/// move, `vm exec`, the purge. About six minutes.
#[test]
#[ignore = "live, S11 part C, F1: a git checkout -b carried across a re-address (about six minutes; six Touch IDs: the chat, the test process's runtime key, the terminate, the move, vm exec, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S11_TESTS=1 make test-aws S11=1"]
fn live_s11_checkout_b_then_readdress() {
    const TEST: &str = "live_s11_checkout_b_then_readdress";
    if !s11_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s11_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s11-checkout-b");
    let path = ws.display().to_string();
    let wsref = ai_env_cli::bridge::workspace::resolve(&live.cfg, &ws, None).unwrap_or_else(|e| panic!("{TEST}: the fixture's workspace: {e}"));
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let fetched = live_audit(&live, audit_event::CODEOUT_FETCH).len();
    let made = chat.turn("Run exactly this command with your Bash tool, then reply with its output only: git checkout -b topic && git branch --show-current");
    assert_eq!(made.result["is_error"], false, "{TEST}: {}", made.result);
    assert!(made.tool_output.contains("topic"), "{TEST}: the VM's checkout on topic: {}", made.tool_output);
    chat.wait_for("the turn's codeout_fetch row", LIVE_SYNC_LIMIT, Asks::AllowAll, || (live_audit(&live, audit_event::CODEOUT_FETCH).len() > fetched).then_some(()));
    let vm1 = chat.session_vm(&live);
    // The turn's own fetch: the first row of that VM after the turn (a later one may say nothing new).
    let fetches = live_audit(&live, audit_event::CODEOUT_FETCH);
    let codeout = fetches.iter().skip(fetched).find(|r| r["detail"]["vm"] == vm1.as_str()).unwrap_or_else(|| panic!("{TEST}: no codeout_fetch row of {vm1} after the turn: {fetches:?}"));
    eprintln!("{TEST}: codeout_fetch {}", codeout["detail"]);
    assert_eq!(codeout["detail"]["bytes"].as_str(), Some("0"), "{TEST}: a manifest-only 200, no pack: {}", codeout["detail"]);
    let record = ai_env_cli::bridge::workspace::rows::row_of(&live.paths, &wsref)
        .unwrap_or_else(|e| panic!("{TEST}: the workspace row: {e}"))
        .and_then(|r| r.vm.get(&vm1).and_then(|s| s.fetched.clone()))
        .unwrap_or_else(|| panic!("{TEST}: no fetch record of {vm1} in the workspace row"));
    eprintln!("{TEST}: {vm1}'s fetch record: head {} branch {:?}", record.head, record.branch);
    assert_eq!(record.branch.as_deref(), Some("topic"), "{TEST}: the fetch record names the VM's branch");
    let terminate = chat.terminate_mid_turn(&live, &vm1, None);
    // Idle: the move waits for the next message (L5), and the note says so.
    let note = remote::note_move_at_next(&vm1, LossCause::VmGone);
    if chat.read_until(LIVE_LOSS_NOTE_LIMIT, Asks::AllowAll, |v| is_note(v, &note)).is_none() {
        let err = chat.stderr_now();
        panic!("{TEST}: no note within {LIVE_LOSS_NOTE_LIMIT:?} that the chat moves with the next message ({note:?}); the wrapper's stderr: {err}");
    }
    announce_touch_id(TEST, &format!("the move off {vm1} with the next message: the setup-token for the new VM (M1)"));
    let next = chat.turn_within("Reply with exactly OK", LIVE_MOVE_TURN_LIMIT);
    assert_eq!(next.result["is_error"], false, "{TEST}: {}", next.result);
    let vm2 = chat.session_vm(&live);
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    assert!(next.notes.contains(&remote::note_continues(&vm2)), "{TEST}: the notes: {:?}", next.notes);
    let session = chat.session.clone().expect("the chat's session id");
    let (_, end) = moved_rows(TEST, &live, chat.pid(), &session, "readdress", ("cause", "vm_gone"), (&vm1, &vm2));
    assert_eq!((end["detail"]["seed"].as_str(), end["detail"]["touchid"].as_str()), (Some("box"), Some("asked")), "{TEST}: the seed is the dead VM's fetch record (on topic); the move asked its Touch ID (M1)");
    announce_touch_id(TEST, &format!("vm exec in {vm2}: git branch --show-current"));
    let exec = ai_env_live(&live, &["vm", "exec", &vm2, "--", "git", "-C", &path, "branch", "--show-current"]);
    let branch = String::from_utf8_lossy(&exec.stdout).trim().to_string();
    eprintln!("{TEST}: {vm2}'s checkout at {path} is on {branch:?}");
    assert_eq!((exec.status.code(), branch.as_str()), (Some(0), "topic"), "{TEST}: the new VM's branch");
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([1, 0, 0]), "{TEST}: one re-address in the census");
    let out = chat.output();
    sweep_live(&live, &[&out, &terminate, &exec], &[]);
}

/// T11 live, C-4 (C §C.2): a move mid-turn after `/compact` cuts at the turn's
/// parent. Turn 1 `Reply with exactly OK`; turn 2 `/compact`: claude writes
/// its boundary and summary (a `compact_boundary` line in the stream), and the
/// turn's sync commits it before turn 3 ([`Chat::wait_for_sync`]). Turn 3, a
/// prompt holding a nonce, runs `sleep 90; echo slept-<nonce>` (S10's 90 s:
/// under the Bash tool's 2-minute default, which the second run must not
/// reach; claude 2.1.305 runs it unasked, `is_tool_use`); at its Bash call
/// `vm terminate` ends the VM, the wrapper moves the chat and sends the line
/// again. The move's `session_move_end` `cut` and the end row's `cut:` agree
/// and are `at` (the cut at the compaction's parent) or `none` (after a cut
/// miss's retry): printed, part B records which. Turn 3's result comes once,
/// and the chat's view on the Mac lists the nonce's prompt once. Five Touch
/// IDs: the chat, the test process's runtime key, the terminate, the move, the
/// purge. About eight minutes.
#[test]
#[ignore = "live, S11 part C, C-4: a MicroVM terminated mid-turn after /compact and the chat moved (about eight minutes; five Touch IDs: the chat, the test process's runtime key, the terminate, the move, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S11_TESTS=1 make test-aws S11=1"]
fn live_s11_compact_then_move() {
    const TEST: &str = "live_s11_compact_then_move";
    // /compact asks the model for the summary.
    const COMPACT_LIMIT: Duration = Duration::from_secs(300);
    // The sleep's turn: its first run cut by the terminate, the move, then its second run whole.
    const SLEEP_TURN_LIMIT: Duration = Duration::from_secs(600);
    if !s11_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s11_world(&[]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s11-compact-move");
    let mut chat = Chat::open(TEST, &live, &ws, &[]);
    chat.initialize();
    let ok = chat.turn("Reply with exactly OK");
    assert_eq!(ok.result["is_error"], false, "{TEST}: turn 1: {}", ok.result);
    let committed = chat.wait_for_sync(&live, 0);
    let uuid = chat.send_user("/compact");
    let mut systems: Vec<String> = Vec::new();
    let ended = chat.read_until(COMPACT_LIMIT, Asks::AllowAll, |v| {
        if v["type"] == "system" {
            systems.push(v["subtype"].as_str().unwrap_or("?").to_string());
        }
        v["type"] == "result"
    });
    if ended.is_none() {
        let err = chat.stderr_now();
        panic!("{TEST}: /compact ended no turn within {COMPACT_LIMIT:?} (the stream's system lines: {systems:?}); the wrapper's stderr: {err}");
    }
    let compacted = chat.turn_to_result(&uuid, COMPACT_LIMIT);
    // A boundary said just after the result counts too.
    let _ = chat.read_until(Duration::from_secs(3), Asks::AllowAll, |v| {
        if v["type"] == "system" {
            systems.push(v["subtype"].as_str().unwrap_or("?").to_string());
        }
        false
    });
    eprintln!("{TEST}: /compact took {} ms; the stream's system lines {systems:?}", compacted.ms);
    assert_eq!(compacted.result["is_error"], false, "{TEST}: /compact: {}", compacted.result);
    assert!(systems.iter().any(|s| s == "compact_boundary"), "{TEST}: /compact wrote no boundary (the stream's system lines: {systems:?})");
    chat.wait_for_sync(&live, committed);
    let vm1 = chat.session_vm(&live);
    let nonce = live_word("ember");
    let marker = format!("slept-{nonce}");
    let uuid = chat.send_user(&format!("Run exactly this command with your Bash tool, then reply with its output only: sleep 90; echo {marker}"));
    if chat.read_until(LIVE_TURN_LIMIT, Asks::AllowAll, |v| is_permission_for(v, "Bash") || is_tool_use(v, "Bash")).is_none() {
        let err = chat.stderr_now();
        panic!("{TEST}: no Bash call within {LIVE_TURN_LIMIT:?}; the wrapper's stderr: {err}");
    }
    // The sleep runs in the VM: the VM ends under it.
    chat.idle(Duration::from_secs(5));
    let terminate = chat.terminate_mid_turn(&live, &vm1, Some(&format!("right after vm terminate's: the move off {vm1}, the setup-token for the new VM (M1)")));
    let turn = chat.turn_to_result(&uuid, SLEEP_TURN_LIMIT);
    let vm2 = chat.session_vm(&live);
    eprintln!(
        "{TEST}: turn 3 ended after {} ms on {vm2}: notes {:?}, asked {:?}, withdrawn {:?}, echoes {}, inits {}, results {}",
        turn.ms, turn.notes, turn.asked, turn.cancels, turn.echoes, turn.inits, turn.results
    );
    assert_eq!(turn.result["is_error"], false, "{TEST}: turn 3 sent again: {}", turn.result);
    assert_ne!(vm2, vm1, "{TEST}: a new VM");
    assert_eq!(turn.results, 1, "{TEST}: turn 3's result came once");
    let session = chat.session.clone().expect("the chat's session id");
    let (_, end) = moved_rows(TEST, &live, chat.pid(), &session, "readdress", ("cause", "vm_gone"), (&vm1, &vm2));
    let cut = end["detail"]["cut"].as_str().unwrap_or_default().to_string();
    eprintln!("{TEST}: the move's cut after /compact: {cut} (at: the cut at the compaction's parent; none: after a cut miss's retry)");
    assert!(cut == "at" || cut == "none", "{TEST}: the move's cut: {}", end["detail"]);
    chat.wait_for("the view lists turn 3's prompt", LIVE_SYNC_LIMIT, Asks::AllowAll, || (prompt_lines(&view_lines_now(&live, &session), &marker) > 0).then_some(()));
    let (code, close) = chat.close();
    let row = assert_closed_well(TEST, &live, &chat, code, close);
    assert_eq!(row_moves(&row), Some([1, 0, 0]), "{TEST}: one re-address in the census");
    assert_eq!(note_part(&row, census_part::CUT).as_deref(), Some(cut.as_str()), "{TEST}: the end row's cut is the move's");
    let view = assert_a_view(TEST, &live, &session);
    assert_eq!(prompt_lines(&view, &marker), 1, "{TEST}: the view lists the nonce's prompt once");
    let out = chat.output();
    sweep_live(&live, &[&out, &terminate], &[]);
}

/// T11 live, small item f (C §C.6.3): what the CLI writes into a fork's file
/// at its first write, against the fake's FK-3 (S10 §8.4: the fork's first
/// write copies X's user and assistant lines). Chat X: one turn, closed;
/// chat F (`--resume=<X> --fork-session`): one turn, closed, a session of its
/// own. The VM kept running (`suspend_on_close = false`), `vm exec` prints
/// the shape of the two files there ([`fork_shape_script`]: each line's type
/// and uuid, never content), and the test says F's line count and types,
/// whether each of X's user and assistant uuids is in F's file (and the
/// test's own uuid for F's turn), then `matches FK-3` or what differs (a
/// difference is a fix of the fake, C3's file, in part B's step L). It asserts
/// only that F's file exists and holds F's own turn: a user and an assistant
/// line none of X's. Five Touch IDs: two chats, the test process's runtime
/// key, `vm exec`, the purge. About four minutes.
#[test]
#[ignore = "live, S11 part C, the shape of a fork's first transcript write against FK-3 (about four minutes; five Touch IDs: two chats, the test process's runtime key, vm exec, the purge): AI_ENV_AWS_TESTS=1 AI_ENV_S11_TESTS=1 make test-aws S11=1"]
fn live_s11_fork_first_write() {
    const TEST: &str = "live_s11_fork_first_write";
    if !s11_live() {
        return;
    }
    let _signals = Interrupts::catch();
    let live = s11_world(&[("suspend_on_close", toml::Value::Boolean(false)), ("reuse_per_workspace", toml::Value::Boolean(true))]);
    let _purge = PurgeTranscripts(&live);
    let _vms = SessionVms::new(&live);
    let ws = s8_fixture(&live, "live-s11-fork");
    let slug = ai_env_cli::wire::slug::project_dir_name(&ws).expect("the fixture's project directory name");
    let mut x = Chat::open(TEST, &live, &ws, &[]);
    x.initialize();
    let said = x.turn("Reply with exactly OK");
    assert_eq!(said.result["is_error"], false, "{TEST}: chat X: {}", said.result);
    let (code, close) = x.close();
    let xrow = assert_closed_well(TEST, &live, &x, code, close);
    let x_sid = x.session.clone().expect("chat X's session id");
    let resume = format!("--resume={x_sid}");
    let mut f = Chat::open(TEST, &live, &ws, &[&resume, "--fork-session"]);
    f.initialize();
    let own = f.turn("Reply with exactly FORKED");
    assert_eq!(own.result["is_error"], false, "{TEST}: chat F: {}", own.result);
    let (code, close) = f.close();
    let frow = assert_closed_well(TEST, &live, &f, code, close);
    let f_sid = f.session.clone().expect("chat F's session id");
    assert_ne!(f_sid, x_sid, "{TEST}: the fork is a session of its own");
    let vm = note_part(&frow, census_part::VM).expect("chat F's VM");
    eprintln!("{TEST}: X {x_sid} on {:?}, F {f_sid} on {vm} ({:?})", note_part(&xrow, census_part::VM), note_part(&frow, census_part::VM_HOW));
    announce_touch_id(TEST, &format!("vm exec in {vm}: the shape of the fork's file (types and uuids only)"));
    let exec = ai_env_live(&live, &["vm", "exec", &vm, "--", "sh", "-c", &fork_shape_script(&slug, &x_sid, &f_sid)]);
    assert_eq!(exec.status.code(), Some(0), "{TEST}: vm exec");
    let lines = String::from_utf8_lossy(&exec.stdout).to_string();
    let (xs, fs) = fork_shapes(&lines).unwrap_or_else(|| panic!("{TEST}: the shape's lines do not add up:\n{lines}"));
    let types: Vec<&str> = fs.lines.iter().map(|(t, _)| t.as_str()).collect();
    eprintln!("{TEST}: F's file ({}): {} line(s), types in order {types:?}", if fs.present { "present" } else { "absent" }, fs.lines.len());
    let in_f: Vec<&str> = fs.lines.iter().filter_map(|(_, u)| u.as_deref()).collect();
    let yes = |u: &str| if in_f.contains(&u) { "yes" } else { "no" };
    eprintln!("{TEST}: X's file ({}): {} line(s); its user and assistant uuids in F's file: {:?}", if xs.present { "present" } else { "absent" }, xs.lines.len(), xs.messages().iter().map(|u| format!("{u} {}", yes(u))).collect::<Vec<_>>());
    eprintln!("{TEST}: the test's uuid for F's turn ({}) in F's file: {}", own.uuid, yes(&own.uuid));
    match fk3_verdict(&xs, &fs) {
        Ok(()) => eprintln!("{TEST}: matches FK-3"),
        Err(differs) => eprintln!("{TEST}: differs from FK-3: {differs}"),
    }
    assert!(fs.present, "{TEST}: F's file {f_sid}.jsonl exists on {vm}");
    let (own_user, own_assistant) = own_messages(&xs, &fs);
    assert!(own_user >= 1 && own_assistant >= 1, "{TEST}: F's file holds F's own turn: {own_user} user and {own_assistant} assistant line(s) none of X's");
    let (a, b) = (x.output(), f.output());
    sweep_live(&live, &[&a, &b, &exec], &[]);
}
