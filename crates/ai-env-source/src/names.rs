//! Names: sources, ops, worker ids and the relay id (plans/s13-contracts.md §P-proto-sdk.6.8, P-R40).
//!
//! The three checks share one rule today and stay separate so one can change alone (LD-P8).

/// The longest name.
pub const NAME_MAX: usize = 64;
/// The refusal's text.
pub const NAME_RULE: &str = "1 to 64 of [a-z0-9._-], starting with [a-z0-9]";

/// A source's name: `Err(NAME_RULE)` unless P-R40's rule holds.
pub fn check_source_name(name: &str) -> Result<(), String> {
    check(name)
}

/// An op's name: `Err(NAME_RULE)` unless P-R40's rule holds.
pub fn check_op_name(name: &str) -> Result<(), String> {
    check(name)
}

/// A worker id (also the relay id): `Err(NAME_RULE)` unless P-R40's rule holds.
pub fn check_worker_id(id: &str) -> Result<(), String> {
    check(id)
}

fn check(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let first_ok = matches!(bytes.first(), Some(b'a'..=b'z' | b'0'..=b'9'));
    let rest_ok = bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if first_ok && rest_ok && bytes.len() <= NAME_MAX {
        Ok(())
    } else {
        Err(NAME_RULE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P-T15.
    #[test]
    fn names_accept_the_charset_and_refuse_the_rest() {
        type NameCheck = fn(&str) -> Result<(), String>;
        let checks: [(&str, NameCheck); 3] = [("source", check_source_name), ("op", check_op_name), ("worker", check_worker_id)];
        let longest = "a".repeat(NAME_MAX);
        let too_long = "a".repeat(NAME_MAX + 1);
        for (what, check) in checks {
            for good in ["a", "0x", "a.b-c_d", longest.as_str()] {
                assert_eq!(check(good), Ok(()), "{what} {good}");
            }
            for bad in ["", too_long.as_str(), "A", "-a", ".a", "_a", "a*", "a/b", "a b", "a:b", "caf\u{e9}"] {
                assert_eq!(check(bad), Err(NAME_RULE.to_string()), "{what} {bad:?}");
            }
        }
    }
}
