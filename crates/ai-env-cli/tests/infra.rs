//! S3 infrastructure helpers through the real `ai-env` binary (feature
//! `bridge`): `infra scan`, `infra pin`, `infra status`, `infra base-image`,
//! `infra versions-diff`, `creds aws-set`, (S7) `creds setup-token|status|forget`, (A1) `creds account
//! add|use|list|forget` (`infra/accounts.rs`), and (S8 operators) `ai-env as`
//! and the operator identity (`infra/identity.rs`) and `creds deployer-key` (`infra/handover.rs`), with the key
//! shapes of `common/aws_keys.rs`. Each area lives in its own file
//! under tests/infra/ (declared with `#[path]`, so the undeclared-test lint
//! only sees this root). No test touches AWS, the real keystore or the real
//! bridge directory: every run gets a temp `AI_ENV_BRIDGE_DIR`/`AI_ENV_DIR`.

#[path = "infra/common.rs"]
mod common;
#[path = "common/aws_keys.rs"]
mod aws_keys;
#[path = "infra/scan.rs"]
mod scan;
#[path = "infra/pin.rs"]
mod pin;
#[path = "infra/status.rs"]
mod status;
#[path = "infra/creds.rs"]
mod creds;
#[path = "infra/setup_token.rs"]
mod setup_token;
#[path = "infra/accounts.rs"]
mod accounts;
#[path = "infra/image.rs"]
mod image;
#[path = "infra/identity.rs"]
mod identity;
#[path = "infra/handover.rs"]
mod handover;
#[path = "infra/relay.rs"]
mod relay;
#[path = "infra/relay_mac.rs"]
mod relay_mac;
#[path = "infra/relay_joint.rs"]
mod relay_joint;
