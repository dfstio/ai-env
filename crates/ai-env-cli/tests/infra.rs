//! S3 infrastructure helpers through the real `ai-env` binary (feature
//! `bridge`): `infra scan`, `infra pin`, `infra status`, `infra base-image`,
//! `infra versions-diff`, `creds aws-set`, and (S7) `creds setup-token|status|forget`. Each area lives in its own file
//! under tests/infra/ (declared with `#[path]`, so the undeclared-test lint
//! only sees this root). No test touches AWS, the real keystore or the real
//! bridge directory: every run gets a temp `AI_ENV_BRIDGE_DIR`/`AI_ENV_DIR`.

#[path = "infra/common.rs"]
mod common;
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
#[path = "infra/image.rs"]
mod image;
