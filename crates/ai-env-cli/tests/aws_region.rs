//! The one bridge test that mutates the process environment (`AWS_REGION`,
//! `AWS_DEFAULT_REGION`). It lives alone in this binary so it can never race
//! the other `aws` tests, which share a process and read the environment
//! through `sdk_config()`. Declared in Cargo.toml (`autotests = false`) with
//! `required-features = ["bridge"]`.
use ai_env_cli::bridge::api::sdk_config;

#[tokio::test]
async fn sdk_config_region_pinned_despite_env() {
    std::env::set_var("AWS_REGION", "eu-west-3");
    std::env::set_var("AWS_DEFAULT_REGION", "eu-west-3");
    let cfg = sdk_config().await;
    assert_eq!(cfg.region().map(|r| r.as_ref().to_string()), Some("eu-central-1".to_string()));
    std::env::remove_var("AWS_REGION");
    std::env::remove_var("AWS_DEFAULT_REGION");
}
