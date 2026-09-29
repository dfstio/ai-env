//! Tiny time helpers (no chrono): Unix seconds and RFC 3339 UTC rendering.

/// Seconds since the Unix epoch (0 if the clock is before it).
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch (0 if the clock is before it); the
/// census `start` field, so the S2 teardown gaps (2 s / 5 s) are measurable.
#[must_use]
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp (Howard Hinnant's
/// civil-from-days, the inverse of `commands::days_since`).
#[must_use]
pub fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Unix seconds for `YYYY-MM-DDTHH:MM:SS[.fff]Z` (UTC only, the shape
/// `rfc3339_utc` writes; a fraction is accepted and truncated). `None` for
/// any other shape, an impossible date, or a time before 1970. Hinnant's
/// days-from-civil, the inverse of `rfc3339_utc`. The shape is ASCII-only, so
/// anything else is refused before a byte offset is sliced (a multi-byte
/// character straddling byte 19 would otherwise panic).
#[must_use]
pub fn parse_rfc3339_utc(text: &str) -> Option<u64> {
    if !text.is_ascii() {
        return None;
    }
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || *b.last()? != b'Z' {
        return None;
    }
    let tail = &text[19..text.len() - 1];
    if !tail.is_empty() && !(tail.len() >= 2 && tail.starts_with('.') && tail[1..].bytes().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = &text[r];
        if s.bytes().all(|c| c.is_ascii_digit()) { s.parse().ok() } else { None }
    };
    let (y, mth, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, m, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mth {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if y < 1970 || d < 1 || d > dim || h > 23 || m > 59 || s > 59 {
        return None;
    }
    let yy = if mth <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = if mth > 2 { mth - 3 } else { mth + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + m * 60 + s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_kats() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_789_804_800), "2026-09-19T08:00:00Z");
        assert_eq!(rfc3339_utc(1_789_804_800 + 3661), "2026-09-19T09:01:01Z");
    }

    #[test]
    fn parse_is_the_inverse_of_render() {
        for secs in [0u64, 951_782_400, 1_789_804_800, 1_789_804_800 + 3661, 4_102_444_799, 1_709_164_800] {
            assert_eq!(parse_rfc3339_utc(&rfc3339_utc(secs)), Some(secs), "{}", rfc3339_utc(secs));
        }
        assert_eq!(parse_rfc3339_utc("2026-09-25T01:39:37.123Z"), parse_rfc3339_utc("2026-09-25T01:39:37Z"), "fraction truncated");
    }

    #[test]
    fn parse_rejects_other_shapes() {
        for bad in [
            "",
            "2026-09-25",
            "2026-09-25T01:39:37",
            "2026-09-25T01:39:37+00:00",
            "2026-09-25 01:39:37Z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-09-25T24:00:00Z",
            "2026-09-25T01:60:00Z",
            "1969-12-31T23:59:59Z",
            "2026-09-25T01:39:37.Z",
            "2026-09-25T01:39:37.1aZ",
            "+026-09-25T01:39:37Z",
            "2026-09-25T01:39:3xZ",
            // Multi-byte characters: 'é' straddles byte 19 (a slice there panicked).
            "2026-09-25T01:39:3\u{e9}Z",
            "2026-09-25T01:39:37\u{e9}Z",
            "2026-09-25T01:39:37.\u{e9}Z",
            "2026-0\u{e9}25T01:39:37Z",
            "\u{e9}26-09-25T01:39:37Z",
        ] {
            assert_eq!(parse_rfc3339_utc(bad), None, "{bad:?}");
        }
        assert!(parse_rfc3339_utc("2024-02-29T00:00:00Z").is_some(), "leap day");
    }

    #[test]
    fn now_is_after_2026() {
        assert!(unix_now() > 1_767_225_600);
    }

    #[test]
    fn millis_agree_with_seconds_and_never_go_backwards() {
        let secs = unix_now();
        let a = unix_now_ms();
        let b = unix_now_ms();
        assert!(a >= secs * 1000, "{a} < {secs}s");
        assert!(a / 1000 <= secs + 1, "{a} ms is more than a second past {secs}s");
        assert!(b >= a);
    }
}
