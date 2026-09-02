//! Known-answer tests over REAL age-produced fixtures (see testdata/README.md
//! for the exact generating commands and tool versions).
//!
//! These freeze the tag derivation (gate G3): if `p256tag_tag` ever computes
//! anything else — e.g. because someone "fixes" the HKDF argument order —
//! these fail loudly instead of ai-env silently resolving no keys.
use ai_env_age::{
    decode_recipient, is_age, match_recipients, p256tag_tag, parse, MatchResult, Recipient,
    StanzaKind,
};

/// The recipient that testdata/test-tag.age and testdata/dual.age are
/// encrypted to (age-plugin-se 0.2.1, --recipient-type=tag).
const REC_TAG: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
/// A different SE key's recipient — testdata/foreign.age is encrypted to it.
const REC_FOREIGN: &str = "age1tag1qv5pjtsk9c4p8gw6uhcsz8k2zsm2tvhxl4jq0sa2mu0gy7d4j8lhgwd2tuv";

fn point(s: &str) -> [u8; 33] {
    match decode_recipient(s).unwrap() {
        Recipient::Tag(p) => p,
        other => panic!("expected tag recipient, got {other:?}"),
    }
}

#[test]
fn recipient_decodes_to_compressed_point() {
    let p = point(REC_TAG);
    assert!(p[0] == 0x02 || p[0] == 0x03);
}

#[test]
fn frozen_tag_kat() {
    // Hand-extracted from testdata/test-tag.age (gate G3):
    //   stanza: -> p256tag UqDsiQ BA0W0yGw…
    // tag 52a0ec89 must equal HKDF-Extract(salt, enc||SHA256(recip)[..4])[..4]
    // with the RFC argument order — Hkdf::extract(Some(salt), ikm).
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/test-tag.age")).unwrap();
    assert!(is_age(&data));
    let header = parse(&data).unwrap();
    assert_eq!(header.stanzas.len(), 1);
    let stanza = &header.stanzas[0];
    assert_eq!(stanza.kind, StanzaKind::P256Tag);
    assert_eq!(stanza.tag4().unwrap(), [0x52, 0xa0, 0xec, 0x89]);

    let enc = stanza.enc65().unwrap();
    assert_eq!(enc.len(), 65);
    assert_eq!(enc[0], 0x04, "X9.63 uncompressed ephemeral");
    assert_eq!(p256tag_tag(&enc, &point(REC_TAG)), [0x52, 0xa0, 0xec, 0x89]);
}

#[test]
fn match_selects_the_right_key() {
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/test-tag.age")).unwrap();
    let header = parse(&data).unwrap();
    let mine = point(REC_TAG);
    let foreign = point(REC_FOREIGN);

    assert_eq!(match_recipients(&header, &[mine]), MatchResult::One(0));
    assert_eq!(match_recipients(&header, &[foreign]), MatchResult::None);
    assert_eq!(match_recipients(&header, &[foreign, mine]), MatchResult::One(1));
}

#[test]
fn dual_recipient_file_matches_and_ignores_x25519() {
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/dual.age")).unwrap();
    let header = parse(&data).unwrap();
    assert_eq!(header.stanzas.len(), 2);
    assert_eq!(header.stanzas[0].kind, StanzaKind::P256Tag);
    assert_eq!(header.stanzas[1].kind, StanzaKind::X25519);
    // The X25519 recovery stanza carries no tag — matching works via p256tag.
    assert_eq!(match_recipients(&header, &[point(REC_TAG)]), MatchResult::One(0));
}

#[test]
fn foreign_file_matches_nothing() {
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/foreign.age")).unwrap();
    let header = parse(&data).unwrap();
    assert_eq!(match_recipients(&header, &[point(REC_TAG)]), MatchResult::None);
    assert_eq!(match_recipients(&header, &[point(REC_FOREIGN)]), MatchResult::One(0));
}

#[test]
fn per_file_tags_differ_for_same_recipient() {
    // Unlinkability: same recipient, different files -> different stanza tags.
    let a = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/test-tag.age")).unwrap();
    let b = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/dual.age")).unwrap();
    let ta = parse(&a).unwrap().stanzas[0].tag4().unwrap();
    let tb = parse(&b).unwrap().stanzas[0].tag4().unwrap();
    assert_ne!(ta, tb);
}
