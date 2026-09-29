//! The one bridge test that mutates the process environment (`AWS_REGION`,
//! `AWS_DEFAULT_REGION`, the endpoint, FIPS/dual-stack and profile variables).
//! It lives alone in this binary, as ONE test fn, so it can never race the
//! other `aws` tests, which share a process and read the environment through
//! `sdk_config()`. Declared in Cargo.toml (`autotests = false`) with
//! `required-features = ["bridge"]`.
use ai_env_cli::bridge::api::{sdk_config, IdleSpec, MicrovmApi, RunSpec, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::vm::client::{connect, sdk_config_for, RuntimeCreds, CONTROL_PLANE_URL};
use ai_env_cli::errors::CliError;
use aws_sdk_lambdamicrovms::config::interceptors::BeforeTransmitInterceptorContextRef;
use aws_sdk_lambdamicrovms::config::{ConfigBag, Credentials, Intercept, RuntimeComponents};
use aws_sdk_lambdamicrovms::error::BoxError;
use std::sync::{Arc, Mutex};

/// Everything aws-config would otherwise honour to move a request (plan §3
/// "SDK environment leaks"), set to hostile values.
const HOSTILE_ENV: [(&str, &str); 7] = [
    ("AWS_REGION", "eu-west-3"),
    ("AWS_DEFAULT_REGION", "eu-west-3"),
    ("AWS_ENDPOINT_URL", "http://127.0.0.1:9"),
    ("AWS_ENDPOINT_URL_LAMBDA_MICROVMS", "http://127.0.0.1:9"),
    ("AWS_USE_FIPS_ENDPOINT", "true"),
    ("AWS_USE_DUALSTACK_ENDPOINT", "true"),
    ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false"),
];

/// Variables set from paths or per phase at run time (removed with the others).
const PATH_ENV: [&str; 4] = ["AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ENDPOINT_URL_STS"];

/// Removes every variable this test set, also when an assertion panics.
struct EnvGuard;

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, _) in HOSTILE_ENV {
            std::env::remove_var(k);
        }
        for k in PATH_ENV {
            std::env::remove_var(k);
        }
    }
}

/// Records the URI of every request and stops it before transmission: the
/// endpoint the SDK resolved, checked offline.
#[derive(Debug, Clone, Default)]
struct CaptureUri(Arc<Mutex<Vec<String>>>);

impl Intercept for CaptureUri {
    fn name(&self) -> &'static str {
        "CaptureUri"
    }

    fn read_before_transmit(&self, ctx: &BeforeTransmitInterceptorContextRef<'_>, _rc: &RuntimeComponents, _cfg: &mut ConfigBag) -> Result<(), BoxError> {
        self.0.lock().unwrap().push(ctx.request().uri().to_string());
        Err("captured before transmit: nothing is sent".into())
    }
}

impl CaptureUri {
    fn uris(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

fn assert_pinned(cfg: &aws_config::SdkConfig, what: &str) {
    assert_eq!(cfg.region().map(|r| r.as_ref().to_string()).as_deref(), Some("eu-central-1"), "{what}: region");
    assert_eq!(cfg.endpoint_url(), Some(CONTROL_PLANE_URL), "{what}: endpoint");
    assert_eq!(cfg.use_fips(), Some(false), "{what}: FIPS");
    assert_eq!(cfg.use_dual_stack(), Some(false), "{what}: dual-stack");
    assert!(cfg.http_client().is_some(), "{what}: the bridge's TLS client");
}

/// An access key id and a secret of the right shapes, built at run time (no credential-shaped literal).
fn key_pair() -> (String, String) {
    (format!("AKIA{}", "RGON".repeat(4)), format!("{}{}", "eF3+".repeat(9), "gH4/"))
}

fn static_creds() -> RuntimeCreds {
    let (id, secret) = key_pair();
    RuntimeCreds::Static(Credentials::new(id, secret, None, None, "ai-env-test"))
}

/// A request through `client` resolves to the pinned control plane.
async fn assert_request_goes_to_the_control_plane(client: &aws_sdk_lambdamicrovms::Client, what: &str) {
    let cap = CaptureUri::default();
    let e = client.list_microvms().customize().interceptor(cap.clone()).send().await.unwrap_err();
    let uris = cap.uris();
    assert_eq!(uris.len(), 1, "{what}: one attempt, stopped before transmit ({})", aws_sdk_lambdamicrovms::error::DisplayErrorContext(&e));
    assert!(uris[0].starts_with(&format!("{CONTROL_PLANE_URL}/")), "{what}: {}", uris[0]);
}

fn run_spec() -> RunSpec {
    RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        execution_role_arn: None,
        ingress_connectors: vec![],
        egress_connectors: vec![],
        idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
        max_duration_s: 900,
        run_hook_payload: "{}".into(),
        client_token: "01926f2e-0000-7000-8000-00000000a0e1".into(),
    }
}

/// Profile mode with a configuration that would move the assume-role STS call:
/// every call is `Config` (exit 1) naming `names`, before any credential is
/// resolved — nothing reaches the control plane or the STS listener.
async fn assert_profile_refused(profile: &str, names: &str) {
    let api = connect(&RuntimeCreds::Profile(profile.to_string())).await;
    let e = api.list(None).await.unwrap_err();
    let text = e.to_string();
    assert!(matches!(e, BridgeError::Config(_)) && text.contains(names), "{profile}: {text}");
    assert_eq!(CliError::from(e).exit_code(), 1);
    let e = api.run(&run_spec()).await.unwrap_err();
    assert!(matches!(e, BridgeError::Config(_)), "{profile}: never ambiguous, nothing was resolved or sent: {e}");
    let cap = CaptureUri::default();
    api.client().list_microvms().customize().interceptor(cap.clone()).send().await.unwrap_err();
    assert!(cap.uris().is_empty(), "{profile}: the raw client refuses too, before transmit");
}

#[tokio::test]
async fn sdk_config_region_pinned_despite_env() {
    // A listener standing in for a hostile STS endpoint: it must never see a connection.
    let sts = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    sts.set_nonblocking(true).unwrap();
    let sts_url = format!("http://{}", sts.local_addr().unwrap());
    let role = "arn:aws:iam::123456789012:role/ai-env-probe";
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(
        &config,
        format!(
            "[default]\nregion = eu-west-3\nendpoint_url = http://127.0.0.1:9\nuse_fips_endpoint = true\nuse_dualstack_endpoint = true\nservices = hostile\n\n\
             [services hostile]\nlambda_microvms =\n  endpoint_url = http://127.0.0.1:9\nsts =\n  endpoint_url = {sts_url}\n\n\
             [profile ai-env-ar]\nrole_arn = {role}\nsource_profile = ai-env-src\n\n\
             [profile ai-env-src]\nregion = eu-central-1\n\n\
             [profile ai-env-ar-endpoint]\nrole_arn = {role}\nsource_profile = ai-env-src\nendpoint_url = {sts_url}\n\n\
             [profile ai-env-ar-services]\nrole_arn = {role}\nsource_profile = ai-env-src-services\n\n\
             [profile ai-env-src-services]\nservices = hostile\n"
        ),
    )
    .unwrap();
    let (id, secret) = key_pair();
    let credentials = dir.path().join("credentials");
    let keys = format!("aws_access_key_id = {id}\naws_secret_access_key = {secret}\n");
    std::fs::write(&credentials, format!("[ai-env-src]\n{keys}\n[ai-env-src-services]\n{keys}")).unwrap();
    let _guard = EnvGuard;
    for (k, v) in HOSTILE_ENV {
        std::env::set_var(k, v);
    }
    std::env::set_var("AWS_CONFIG_FILE", &config);
    std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &credentials);

    // A profile that does not exist, then the hostile [default] profile itself.
    for profile in [Some("ai-env-missing-profile"), None] {
        match profile {
            Some(p) => std::env::set_var("AWS_PROFILE", p),
            None => std::env::remove_var("AWS_PROFILE"),
        }
        let what = format!("AWS_PROFILE={profile:?}");
        assert_pinned(&sdk_config().await, &format!("{what}, api::sdk_config (default chain)"));
        let cfg = sdk_config_for(&static_creds()).await;
        assert_pinned(&cfg, &format!("{what}, static credentials"));
        assert_request_goes_to_the_control_plane(&aws_sdk_lambdamicrovms::Client::new(&cfg), &format!("{what}, Client::new(sdk_config_for(Static))")).await;
        let api = connect(&static_creds()).await;
        assert_request_goes_to_the_control_plane(api.client(), &format!("{what}, vm::client::connect(Static)")).await;
    }

    // Profile mode: the assume-role STS call is the one hop no SDK setter pins
    // (aws-config builds it from the process environment and the profile), so
    // every configuration that would move it is refused before anything resolves.
    assert_pinned(&sdk_config_for(&RuntimeCreds::Profile("ai-env-ar".into())).await, "profile credentials");
    std::env::set_var("AWS_ENDPOINT_URL", &sts_url);
    std::env::set_var("AWS_ENDPOINT_URL_STS", &sts_url);
    assert_profile_refused("ai-env-ar", "AWS_ENDPOINT_URL is set").await;
    std::env::remove_var("AWS_ENDPOINT_URL");
    std::env::set_var("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true");
    assert_profile_refused("ai-env-ar", "AWS_ENDPOINT_URL_STS is set").await;
    std::env::remove_var("AWS_ENDPOINT_URL_STS");
    assert_profile_refused("ai-env-ar-endpoint", "profile ai-env-ar-endpoint sets endpoint_url in the config file").await;
    assert_profile_refused("ai-env-ar-services", "profile ai-env-src-services (source_profile chain of ai-env-ar-services) sets services").await;
    match sts.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("the hostile STS endpoint was dialled: {other:?}"),
    }

    // A credential failure while resolving the identity for RunMicrovm happens
    // before anything is transmitted: exit 5, never "ambiguous" (which would
    // retry and keep a pending row blocking a max_concurrent slot).
    let api = connect(&RuntimeCreds::Profile("ai-env-missing-profile".into())).await;
    let e = api.run(&run_spec()).await.unwrap_err();
    assert!(matches!(e, BridgeError::CredentialsUnavailable(_)), "{e}");
    assert_eq!(CliError::from(e).exit_code(), 5);
}
