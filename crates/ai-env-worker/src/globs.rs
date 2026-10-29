//! Ids, globs and rules (WM-R1, WM-R2).

use ai_env_source::names;

/// The longest glob: `ai_env_source::names::NAME_MAX`.
pub const GLOB_MAX: usize = 64;
/// The most `*` in one glob.
pub const GLOB_STARS_MAX: usize = 4;

/// The VM registry's pending prefix, refused in any case (`vm::registry::is_vm_id`).
const PENDING_PREFIX: &str = "pending-";

/// A character of §P's names: `[a-z0-9._-]`.
fn name_char(c: u8) -> bool {
    matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')
}

/// §P's name grammar: `names::check_worker_id(s).is_ok()`.
pub fn valid_id(s: &str) -> bool {
    names::check_worker_id(s).is_ok()
}

/// 1 to 64 characters of the name alphabet plus `*`, at most 4 `*`, starting with `[a-z0-9*]`.
pub fn valid_glob(s: &str) -> bool {
    let b = s.as_bytes();
    matches!(b.first(), Some(b'a'..=b'z' | b'0'..=b'9' | b'*'))
        && b.len() <= GLOB_MAX
        && b.iter().all(|&c| name_char(c) || c == b'*')
        && b.iter().filter(|&&c| c == b'*').count() <= GLOB_STARS_MAX
}

/// `*` matches any run of name characters (the empty run too); the glob matches the whole name. A glob
/// WM-R1 refuses, or a name §P refuses, matches nothing.
pub fn glob_match(glob: &str, name: &str) -> bool {
    valid_glob(glob) && names::check_source_name(name).is_ok() && wild(glob.as_bytes(), name.as_bytes())
}

/// The match itself: every glob character but `*` matches itself; on a mismatch the last `*` takes one
/// more character and the rest is tried again.
fn wild(glob: &[u8], name: &[u8]) -> bool {
    let (mut g, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if glob.get(g) == Some(&b'*') {
            star = Some((g, n));
            g += 1;
        } else if glob.get(g) == Some(&name[n]) {
            g += 1;
            n += 1;
        } else if let Some((sg, sn)) = star {
            star = Some((sg, sn + 1));
            g = sg + 1;
            n = sn + 1;
        } else {
            return false;
        }
    }
    glob[g..].iter().all(|&c| c == b'*')
}

/// `<source-glob>/<op-glob>`.
pub fn valid_rule(rule: &str) -> bool {
    rule.split_once('/').is_some_and(|(source, op)| valid_glob(source) && valid_glob(op))
}

/// Both halves of the rule match.
pub fn rule_match(rule: &str, source: &str, op: &str) -> bool {
    valid_rule(rule) && rule.split_once('/').is_some_and(|(s, o)| glob_match(s, source) && glob_match(o, op))
}

/// 1 to 128 of `[A-Za-z0-9-]`, not starting with `-` nor `pending-` in any case.
pub fn valid_vm_id(s: &str) -> bool {
    let pending = s.get(..PENDING_PREFIX.len()).is_some_and(|p| p.eq_ignore_ascii_case(PENDING_PREFIX));
    !s.is_empty() && s.len() <= 128 && !s.starts_with('-') && !pending && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// The canonical lowercase `8-4-4-4-12` hex form, any version.
pub fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// The relay id: §P's name (P-R40), `names::check_source_name`'s rule (WM-R2, review A-L10).
pub fn valid_relay_id(s: &str) -> bool {
    names::check_source_name(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WM-T1.
    #[test]
    fn ids_globs_and_rules_follow_the_grammar() {
        for id in ["a", "w1", "example-echo", "a.b_c-d", &"a".repeat(64)] {
            assert!(valid_id(id), "{id} is an id");
        }
        for not in ["", &"a".repeat(65), "A", "-a", ".a", "a b", "a/b", "a*"] {
            assert!(!valid_id(not), "{not:?} is no id");
        }

        for glob in ["*", "example-*", "*-test", "a*b*c*d*e"] {
            assert!(valid_glob(glob), "{glob} is a glob");
        }
        let six_over = format!("**{}", "x".repeat(GLOB_MAX - 2 + 6));
        for not in ["*****", "a*b*c*d*e*f", "?", "[a]", "", "-a*", six_over.as_str()] {
            assert!(!valid_glob(not), "{not:?} is no glob");
        }
        for byte in 0u8..=127 {
            let one = (byte as char).to_string();
            assert_eq!(valid_glob(&one), valid_id(&one) || byte == b'*', "byte {byte}");
        }

        assert!(glob_match("example-*", "example-"));
        assert!(glob_match("example-*", "example-x"));
        assert!(!glob_match("example-*", "xexample-y"));
        for id in ["a", "w1", "example-echo", "a.b_c-d", &"z".repeat(64)] {
            assert!(glob_match("*", id), "* matches {id}");
        }
        assert!(glob_match("a*c", "ac"));
        assert!(glob_match("a*c", "abbc"));
        assert!(!glob_match("a*c", "acb"));
        assert!(glob_match("*-test", "a-test"));
        assert!(glob_match("a*b*c*d*e", "axbxcxdxe"));
        assert!(!glob_match("*", ""), "the empty name is no name");
        assert!(!glob_match("a?", "ab"), "no `?`");
        assert!(!glob_match("*****", "a"), "an invalid glob matches nothing");

        assert!(rule_match("example-*/get", "example-a", "get"));
        assert!(!rule_match("example-*/get", "example-a", "put"));
        assert!(!rule_match("example-*/get", "other-a", "get"));
        assert!(rule_match("*/*", "example-a", "put"));
        assert!(valid_rule("example-*/get"));
        for not in ["a", "a/", "/b", "a/b/c"] {
            assert!(!valid_rule(not), "{not:?} is no rule");
        }
    }

    /// WM-T2.
    #[test]
    fn vm_ids_uuids_and_relay_ids() {
        for vm in ["microvm-0199a1b2-0000-7000-8000-000000000001", "vm-0000"] {
            assert!(valid_vm_id(vm), "{vm} is a VM id");
        }
        for not in ["-x", "pending-x", "Pending-x", "a.b", &"a".repeat(129), ""] {
            assert!(!valid_vm_id(not), "{not:?} is no VM id");
        }

        let uuid = "0199a1b2-0000-7000-8000-000000000002";
        assert!(valid_uuid(uuid));
        assert!(!valid_uuid("0199A1B2-0000-7000-8000-00000000000A"), "uppercase");
        assert!(!valid_uuid(&uuid[..35]), "35 characters");
        assert!(!valid_uuid("0199a1b2x0000-7000-8000-000000000002"), "a hyphen missing");

        assert!(valid_relay_id("relay-test"));
        for not in ["relay test", "Relay", &"r".repeat(65)] {
            assert!(!valid_relay_id(not), "{not:?} is no relay id");
        }
    }
}
