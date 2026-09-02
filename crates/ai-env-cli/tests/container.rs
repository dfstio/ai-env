#![allow(dead_code)] // the included modules expose more than these tests use
//! Container format tests — the G6-frozen behavior.
//!
//! NOTE: this integration test exercises the format through the binary's own
//! modules by round-tripping real files in a temp dir with a fake `age` on
//! PATH where needed; the pure read/write logic is included directly.
#[path = "../src/errors.rs"]
mod errors;
#[path = "../src/container.rs"]
mod container;

// (errors.rs #[macro_export]s `bail!` at this test-crate's root, which is
// exactly where the included container.rs expects to find it.)

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// A syntactically valid binary age blob (header only) for payload tests.
fn fake_age_blob() -> Vec<u8> {
    b"age-encryption.org/v1\n-> X25519 khoXd2sWaTNKEb7dTUL87qKzHuBEz1RiXAiy+qglEUs\njHicmFkEVk3BVJetg/2AO9wwNegUrXDk9QASQ4tjyt0\n--- pNfQeiGYtytc9efKtA2pqwr6uCCweANDDaxRZgjCy64\npayload".to_vec()
}

#[test]
fn roundtrip() {
    let blob = fake_age_blob();
    let text = container::write(&blob);
    assert!(container::has_marker(&text));
    assert!(container::detect(&text));
    let read = container::read(&text).unwrap();
    assert_eq!(read.data, blob);
    assert_eq!(read.version, 1);
    // Single-line payload, unquoted (docker G7).
    let data_line = text.lines().find(|l| l.starts_with("AI_ENV_DATA=")).unwrap();
    assert!(!data_line.contains('"'));
    assert_eq!(text.lines().filter(|l| l.starts_with("AI_ENV_DATA=")).count(), 1);
}

#[test]
fn tolerates_crlf_and_hand_quoting() {
    let blob = fake_age_blob();
    let b64 = B64.encode(&blob);
    // CRLF checkout:
    let crlf = format!("AI_ENV=1\r\nAI_ENV_DATA={b64}\r\n");
    assert_eq!(container::read(&crlf).unwrap().data, blob);
    // Someone hand-quoted the value:
    let quoted = format!("AI_ENV=1\nAI_ENV_DATA=\"{b64}\"\n");
    assert_eq!(container::read(&quoted).unwrap().data, blob);
}

#[test]
fn rejects_broken_containers() {
    // Marker but no data.
    assert!(container::read("AI_ENV=1\n").is_err());
    // Bad base64.
    assert!(container::read("AI_ENV=1\nAI_ENV_DATA=!!!\n").is_err());
    // Valid base64, not age.
    let junk = B64.encode(b"not age at all");
    assert!(container::read(&format!("AI_ENV=1\nAI_ENV_DATA={junk}\n")).is_err());
    // No marker at all.
    assert!(!container::has_marker("FOO=bar\n"));
    assert!(container::read("FOO=bar\n").is_err());
    // Future version is a clean "upgrade" error, not corrupt.
    let b64 = B64.encode(fake_age_blob());
    let future = format!("AI_ENV=1\nAI_ENV_VERSION=2\nAI_ENV_DATA={b64}\n");
    let err = container::read(&future).unwrap_err();
    assert_eq!(err.exit_code(), 1, "future version should ask to upgrade, got {err}");
}

#[test]
fn plaintext_with_ai_env_var_is_not_detected() {
    // A legitimate plaintext .env that happens to define AI_ENV=1 but has no
    // decodable payload must NOT be detected as a container.
    assert!(!container::detect("AI_ENV=1\nOTHER=x\n"));
}

#[test]
fn size_cap_math_stays_under_dockers_line_limit() {
    // The whole point of MAX_PLAINTEXT: the emitted AI_ENV_DATA line must
    // stay under docker's 65,536-byte line cap (observed live in gate G7).
    let overhead = 500; // age header for a few recipients + MAC + framing
    let encoded = 4 * (container::MAX_PLAINTEXT + overhead) / 3;
    assert!(
        "AI_ENV_DATA=".len() + encoded < 65_536,
        "MAX_PLAINTEXT too large for docker --env-file"
    );
}
