//! S8 operators: AWS key shapes built at run time (no credential-shaped
//! literal anywhere in the sources), the stack's Pulumi passphrase likewise
//! (A39), and the environment `ai-env as` leaves
//! (plans/s8-operators-contracts.md §11.1). A fake key id is `AKIA`, `FAKE`
//! and twelve digits, as tests/fakes/aws.sh, aws-state.sh and ai-env.sh build
//! it; its last four characters are its tail, which `FAKE_AWS_KEY_USERS` maps
//! to a user (by default the three tails below). Declared with `#[path]` by
//! tests/infra.rs and tests/vm.rs.
#![allow(dead_code)]

/// `ai-env-deployer`'s tail in the fakes.
pub const DEPLOYER_TAIL: &str = "9001";
/// `ai-env-ops`'s tail in the fakes.
pub const OPS_TAIL: &str = "9002";
/// `ai-env-runtime`'s tail in the fakes.
pub const RUNTIME_TAIL: &str = "9003";

/// The secret of [`identity_env`], the one tests/fakes/ai-env.sh's runner
/// builds too.
const SECRET_BLOCK: &str = "Dm7/";

/// The block of [`passphrase`].
const PASSPHRASE_BLOCK: &str = "Pf3+";

/// `AKIA`, `FAKE`, eight zeros and `tail` (four of 0-9 A-Z): the shape tests/fakes/aws.sh builds.
pub fn key_id(tail: &str) -> String {
    assert!(tail.len() == 4 && tail.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()), "a tail is four of 0-9 A-Z: {tail:?}");
    format!("{}{}{}{tail}", "AKIA", "FAKE", "0".repeat(8))
}

/// 40 characters: `block` (four characters of A-Z a-z 0-9 / +) ten times.
pub fn secret(block: &str) -> String {
    assert!(block.len() == 4 && block.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+'), "a block is four of A-Z a-z 0-9 / +: {block:?}");
    block.repeat(10)
}

/// The JSON `aws iam create-access-key --output json` prints.
pub fn create_access_key_json(user: &str, id: &str, secret: &str) -> String {
    format!(
        "{{\n    \"AccessKey\": {{\n        \"UserName\": \"{user}\",\n        \"AccessKeyId\": \"{id}\",\n        \"Status\": \"Active\",\n        \"SecretAccessKey\": \"{secret}\",\n        \"CreateDate\": \"2026-10-14T10:00:00+00:00\"\n    }}\n}}\n"
    )
}

/// What `ai-env as <role>` leaves: AI_ENV_BRIDGE_AS=<role>:<tail>, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
pub fn identity_env(role: &str, tail: &str) -> Vec<(String, String)> {
    assert!(matches!(role, "deployer" | "ops"), "only ai-env as deployer|ops leaves a key: {role:?}");
    vec![
        ("AI_ENV_BRIDGE_AS".to_string(), format!("{role}:{tail}")),
        ("AWS_ACCESS_KEY_ID".to_string(), key_id(tail)),
        ("AWS_SECRET_ACCESS_KEY".to_string(), secret(SECRET_BLOCK)),
    ]
}

/// The fake stack's Pulumi passphrase (A39), built at run time so no fixture
/// holds it: what tests/fakes/ai-env.sh's `run -f` of a
/// `FAKE-SEALED-PASSPHRASE` file puts in PULUMI_CONFIG_PASSPHRASE, and the one
/// value tests/fakes/pulumi.sh accepts (both build it the same way).
pub fn passphrase() -> String {
    PASSPHRASE_BLOCK.repeat(8)
}

/// What `ai-env as root|ambient` leaves: the marker only.
pub fn marker_env(word: &str) -> Vec<(String, String)> {
    assert!(matches!(word, "root" | "ambient"), "only ai-env as root|ambient leaves the marker alone: {word:?}");
    vec![("AI_ENV_BRIDGE_AS".to_string(), word.to_string())]
}
