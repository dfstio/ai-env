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
            rt.block_on(async {
                let api = connect(&creds).await;
                for id in ids {
                    match vmrun::terminate_and_record(&api, &paths, &id, "test", Some(Poll::SETTLE)).await {
                        Ok(_) => eprintln!("guard: terminated {id}"),
                        Err(e) => eprintln!("guard: could not terminate {id}: {} — run: ai-env vm terminate {id} --yes (the test's row lived in a temp root)", no_account(&e.to_string())),
                    }
                }
            });
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
                match vmrun::adopt_after_ambiguous(api, ep, &live.paths, p, since, Poll::RUNNING).await {
                    Ok(vmrun::Adoption::Adopted(id)) => guard.add(&id),
                    Ok(vmrun::Adoption::Unresolved(ids)) => eprintln!("start: VMs that may be this test's could not be asked: {} — check with ai-env vm gc; ai-env vm terminate <id> --yes", ids.join(", ")),
                    Ok(vmrun::Adoption::NoMatch) => eprintln!("start: no VM of this test's ambiguous run is visible"),
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
