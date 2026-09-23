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
