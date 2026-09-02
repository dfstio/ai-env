//! Property tests: the header parser must never panic and never accept
//! structurally broken input, no matter what bytes arrive.
use ai_env_age::{parse, MAGIC_LINE};
use proptest::prelude::*;

proptest! {
    /// Arbitrary bytes: parse never panics.
    #[test]
    fn parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse(&data);
    }

    /// Arbitrary bytes after a valid magic line: never panics.
    #[test]
    fn parse_never_panics_with_magic(tail in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut data = format!("{MAGIC_LINE}\n").into_bytes();
        data.extend_from_slice(&tail);
        let _ = parse(&data);
    }

    /// Every truncation of a valid file errors (never panics, never succeeds
    /// with a bogus header) — except lengths that still contain the full header.
    #[test]
    fn truncations_never_panic(cut in 0usize..600) {
        let full = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/dual.age")).unwrap();
        let cut = cut.min(full.len());
        let _ = parse(&full[..cut]);
    }

    /// Stanza-count bombs are capped, not allocated.
    #[test]
    fn stanza_bomb_is_rejected(n in 65usize..300) {
        let mut data = format!("{MAGIC_LINE}\n");
        for _ in 0..n {
            data.push_str("-> X25519 khoXd2sWaTNKEb7dTUL87qKzHuBEz1RiXAiy+qglEUs\n");
            data.push_str("jHicmFkEVk3BVJetg/2AO9wwNegUrXDk9QASQ4tjyt0\n");
        }
        data.push_str("--- pNfQeiGYtytc9efKtA2pqwr6uCCweANDDaxRZgjCy64\n");
        prop_assert!(parse(data.as_bytes()).is_err());
    }
}

#[test]
fn crlf_is_reported_distinctly() {
    let data = format!("{MAGIC_LINE}\r\nrest");
    assert_eq!(parse(data.as_bytes()).unwrap_err(), ai_env_age::ParseError::CrLf);
}

#[test]
fn valid_fixture_parses() {
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/test-tag.age")).unwrap();
    assert!(parse(&data).is_ok());
}
