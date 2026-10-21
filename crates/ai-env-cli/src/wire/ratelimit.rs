//! What a Claude account's turns say of its usage limits (S10 addendum A1):
//! claude's `rate_limit_event` line and its usage-limit `result`, read
//! leniently, and the words ai-env shows them in. Pure and serde-only, as
//! [`super::claude`]: the pump's usage tap (`bridge::accounts::usage`) and
//! `creds account check` use them.
//!
//! Shapes (claude 2.1.305, read from its bundle as data; part B pins them
//! from a live run):
//! * `{"type":"rate_limit_event","rate_limit_info":{…},"uuid":…,"session_id":…}`,
//!   one per real turn. Its `rate_limit_info`: `status` (`allowed`,
//!   `allowed_warning`, `rejected`), and optionally `resetsAt` (unix
//!   seconds), `rateLimitType` (a kind of [`LIMIT_NAMES`]), `utilization`
//!   (a fraction), `unifiedWindows` (`five_hour`, `seven_day`, each
//!   `{utilization, resetsAt}`), `overageStatus`, `isUsingOverage`,
//!   `surpassedThreshold` and more. S7's B16 (2.1.296) printed `status`
//!   alone.
//! * A refused turn's `result`: `is_error` true, `api_error`
//!   `usage_limit_reached`, `api_error_status` 429, its `result` the CLI's
//!   text, `You've hit your weekly limit · resets 10am (UTC)` (S10 part B's
//!   B2, 21 Oct 2026: `tests/fixtures/claude/usage-limit-result-2.1.305.json`),
//!   with `api_error_params.rate_limit_info` when the CLI names the limit.
//!   A 429 throttle (`rate_limit`, another text) is no usage limit.
//!
//! A field of an unexpected type reads as absent; an unknown `status` too.
//! Windows are lenient: with no `unifiedWindows`, the top-level
//! `utilization` and `resetsAt` stand in for the `rateLimitType` window
//! when that is `five_hour` or `seven_day` (a setup-token may get no
//! windows at all: part B shows which).
use serde_json::Value;

/// `api_error` of a usage-limit result.
pub const USAGE_LIMIT_ERROR: &str = "usage_limit_reached";
/// The statuses a `rate_limit_info` names.
pub const STATUSES: [&str; 3] = ["allowed", "allowed_warning", "rejected"];
/// Each limit kind (`rateLimitType`) and its name in the CLI's text
/// (`You've hit your <name> · resets …`), as 2.1.305's bundle words them.
pub const LIMIT_NAMES: [(&str, &str); 6] = [
    ("five_hour", "session limit"),
    ("seven_day", "weekly limit"),
    ("seven_day_opus", "Opus limit"),
    ("seven_day_sonnet", "Sonnet limit"),
    ("seven_day_overage_included", "Fable limit"),
    ("overage", "usage credit limit"),
];
/// The most of a limit's text ai-env keeps, in characters.
pub const TEXT_MAX: usize = 300;

/// How the CLI's limit text starts.
const HIT: &str = "You've hit your ";
/// What comes before the reset phrase in it.
const RESETS: &str = " · resets ";

/// One usage window: how much of it is used (a fraction, as given: it may
/// pass 1) and when it resets (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Window {
    pub utilization: f64,
    pub resets_at: u64,
}

/// A `rate_limit_info` object, read leniently.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RateLimitInfo {
    /// One of [`STATUSES`]; `None` when absent or another word.
    pub status: Option<&'static str>,
    pub resets_at: Option<u64>,
    pub rate_limit_type: Option<String>,
    pub utilization: Option<f64>,
    /// `unifiedWindows.five_hour` and `.seven_day`.
    pub five_hour: Option<Window>,
    pub seven_day: Option<Window>,
    pub is_using_overage: bool,
}

impl RateLimitInfo {
    /// The 5-hour and weekly windows it reports: its unified windows, else
    /// the top-level `utilization` and `resetsAt` for its `rateLimitType`
    /// when that is one of the two (the module doc).
    #[must_use]
    pub fn effective(&self) -> (Option<Window>, Option<Window>) {
        if self.five_hour.is_some() || self.seven_day.is_some() {
            return (self.five_hour, self.seven_day);
        }
        let top = self.utilization.zip(self.resets_at).map(|(utilization, resets_at)| Window { utilization, resets_at });
        match self.rate_limit_type.as_deref() {
            Some("five_hour") => (top, None),
            Some("seven_day") => (None, top),
            _ => (None, None),
        }
    }
}

/// A usage-limit result: the CLI's text (control characters blanked, at
/// most [`TEXT_MAX`] characters), the limit's kind (`api_error_params`'
/// `rateLimitType`, else the text's name, [`kind_of_text`]), when it resets
/// when the params say, the HTTP status, and the params' info.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitHit {
    pub text: String,
    pub kind: Option<String>,
    pub resets_at: Option<u64>,
    pub http: Option<u16>,
    pub info: Option<RateLimitInfo>,
}

/// A number as unix seconds or a fraction: an integer, or a float (seconds
/// truncated); anything else is none.
fn seconds(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    v.as_u64().or_else(|| v.as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f as u64))
}

fn fraction(v: Option<&Value>) -> Option<f64> {
    v?.as_f64().filter(|f| f.is_finite())
}

fn window(v: Option<&Value>) -> Option<Window> {
    let v = v?;
    Some(Window { utilization: fraction(v.get("utilization"))?, resets_at: seconds(v.get("resetsAt"))? })
}

/// A `rate_limit_info` object already parsed.
fn info_of(v: &Value) -> Option<RateLimitInfo> {
    if !v.is_object() {
        return None;
    }
    let status = v.get("status").and_then(Value::as_str).and_then(|s| STATUSES.iter().copied().find(|k| *k == s));
    let unified = v.get("unifiedWindows");
    Some(RateLimitInfo {
        status,
        resets_at: seconds(v.get("resetsAt")),
        rate_limit_type: v.get("rateLimitType").and_then(Value::as_str).map(str::to_string),
        utilization: fraction(v.get("utilization")),
        five_hour: window(unified.and_then(|u| u.get("five_hour"))),
        seven_day: window(unified.and_then(|u| u.get("seven_day"))),
        is_using_overage: v.get("isUsingOverage").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// A `rate_limit_info` object's JSON text, read leniently; `None` for no object.
#[must_use]
pub fn parse_info(text: &str) -> Option<RateLimitInfo> {
    info_of(&serde_json::from_str(text).ok()?)
}

/// A whole `rate_limit_event` line's info; `None` for any other line, or
/// one with no info object.
#[must_use]
pub fn parse_event_line(line: &[u8]) -> Option<RateLimitInfo> {
    let v: Value = serde_json::from_slice(line).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("rate_limit_event") {
        return None;
    }
    info_of(v.get("rate_limit_info")?)
}

/// A usage-limit `result` line (the module doc): `type` `result`,
/// `is_error` true, and `api_error` [`USAGE_LIMIT_ERROR`], or
/// `api_error_status` 429 with a text starting `You've hit your `. Any
/// other line, a throttle among them, is none.
#[must_use]
pub fn parse_limit_result(line: &[u8]) -> Option<LimitHit> {
    let v: Value = serde_json::from_slice(line).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("result") || v.get("is_error").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let text = v.get("result").and_then(Value::as_str).unwrap_or_default();
    let http = v.get("api_error_status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok());
    let limit = v.get("api_error").and_then(Value::as_str) == Some(USAGE_LIMIT_ERROR) || (http == Some(429) && text.starts_with(HIT));
    if !limit {
        return None;
    }
    let info = v.pointer("/api_error_params/rate_limit_info").and_then(info_of);
    let kind = info.as_ref().and_then(|i| i.rate_limit_type.clone()).or_else(|| kind_of_text(text).map(str::to_string));
    let resets_at = info.as_ref().and_then(|i| i.resets_at);
    Some(LimitHit { text: shown(text), kind, resets_at, http, info })
}

/// `text` with control characters blanked, at most [`TEXT_MAX`] characters.
fn shown(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(TEXT_MAX).collect()
}

/// The kind the CLI's text names (`You've hit your weekly limit · …`:
/// `seven_day`); `None` for a text that names none of [`LIMIT_NAMES`].
#[must_use]
pub fn kind_of_text(text: &str) -> Option<&'static str> {
    let rest = text.strip_prefix(HIT)?;
    LIMIT_NAMES.iter().find(|(_, name)| rest.starts_with(name)).map(|(kind, _)| *kind)
}

/// The CLI's own words for when the limit resets: what follows ` · resets `
/// in its text (`10am (UTC)`), trimmed; `None` without them.
#[must_use]
pub fn reset_phrase(text: &str) -> Option<&str> {
    text.split_once(RESETS).map(|(_, rest)| rest.trim()).filter(|r| !r.is_empty())
}

/// A kind's name as the CLI's text says it (`weekly limit`); `usage limit`
/// for a kind it does not name.
#[must_use]
pub fn limit_words(kind: &str) -> &'static str {
    LIMIT_NAMES.iter().find(|(k, _)| *k == kind).map_or("usage limit", |(_, name)| name)
}

/// A kind in one word or two, as ai-env's lines show it (`weekly`,
/// `5-hour`); the kind itself for one it does not know.
#[must_use]
pub fn kind_word(kind: &str) -> &str {
    match kind {
        "five_hour" => "5-hour",
        "seven_day" => "weekly",
        "seven_day_opus" => "Opus weekly",
        "seven_day_sonnet" => "Sonnet weekly",
        "seven_day_overage_included" => "Fable weekly",
        "overage" => "usage credit",
        other => other,
    }
}

/// A fraction as a whole percentage (`0.23`: `23%`; it may pass 100).
#[must_use]
pub fn pct(utilization: f64) -> String {
    let p = (utilization * 100.0).round();
    if p.is_finite() && p >= 0.0 {
        format!("{p:.0}%")
    } else {
        "?%".to_string()
    }
}

/// When `at` comes, as seen at `now` (unix seconds, UTC): `HH:MMZ` within
/// 20 hours, `Ddd HH:MMZ` within 6 days, else `Mon DD HH:MMZ`.
#[must_use]
pub fn when(at: u64, now: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let stamp = super::time::rfc3339_utc(at);
    let hm = &stamp[11..16];
    let ahead = at.saturating_sub(now);
    if ahead < 20 * 3600 {
        return format!("{hm}Z");
    }
    if ahead < 6 * 86_400 {
        // 1970-01-01 was a Thursday: day 0 is weekday 4 (Sunday 0).
        let weekday = usize::try_from((at / 86_400 + 4) % 7).unwrap_or(0);
        return format!("{} {hm}Z", DAYS[weekday]);
    }
    let month = stamp[5..7].parse::<usize>().ok().and_then(|m| MONTHS.get(m.wrapping_sub(1))).copied().unwrap_or("???");
    format!("{month} {} {hm}Z", &stamp[8..10])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B2's result, as captured (S10 part B, 21 Oct 2026).
    const B2: &str = include_str!("../../tests/fixtures/claude/usage-limit-result-2.1.305.json");
    /// The constructed events: an `allowed_warning` with both windows, a `rejected` one.
    const CONSTRUCTED: &str = include_str!("../../tests/fixtures/claude/rate-limit-event-constructed-2.1.305.jsonl");
    /// S7 B16's event (2.1.296: its status alone) and B7's refused result.
    const B16: &str = include_str!("../../tests/fixtures/claude/valid-stream-json-2.1.296.jsonl");
    const B7: &str = include_str!("../../tests/fixtures/claude/refused-json-2.1.296.json");
    /// Wed 2026-10-21 08:00Z.
    const NOW: u64 = 1_792_569_600;

    /// B2's real 429 is a weekly limit, told by its text (no params), its
    /// reset phrase `10am (UTC)`, no reset time; its text kept as it is.
    #[test]
    fn the_real_429_is_a_weekly_limit() {
        assert!(B2.ends_with("}\n") && B2.lines().count() == 1, "one line");
        let hit = parse_limit_result(B2.trim_end().as_bytes()).expect("a usage limit");
        assert_eq!(hit, LimitHit { text: "You've hit your weekly limit · resets 10am (UTC)".into(), kind: Some("seven_day".into()), resets_at: None, http: Some(429), info: None });
        assert_eq!(reset_phrase(&hit.text), Some("10am (UTC)"));
        assert_eq!((limit_words("seven_day"), kind_word("seven_day")), ("weekly limit", "weekly"));
    }

    /// `api_error_params.rate_limit_info` names the kind over the text, and
    /// its reset time; a 429 with the CLI's text but another `api_error`
    /// is a limit too; control characters are blanked and the text cut.
    #[test]
    fn the_params_override_the_texts_kind() {
        let with = |params: &str, extra: &str| format!(r#"{{"type":"result","is_error":true,"api_error":"usage_limit_reached","api_error_status":429,"result":"You've hit your weekly limit · resets 10am (UTC)"{extra}{params}}}"#);
        let line = with(r#","api_error_params":{"rate_limit_info":{"status":"rejected","rateLimitType":"seven_day_opus","resetsAt":1792836000}}"#, "");
        let hit = parse_limit_result(line.as_bytes()).unwrap();
        assert_eq!((hit.kind.as_deref(), hit.resets_at), (Some("seven_day_opus"), Some(1_792_836_000)));
        assert_eq!(hit.info.as_ref().and_then(|i| i.status), Some("rejected"));
        let other = r#"{"type":"result","is_error":true,"api_error":"something_new","api_error_status":429,"result":"You've hit your session limit · resets 3pm"}"#;
        assert_eq!(parse_limit_result(other.as_bytes()).and_then(|h| h.kind), Some("five_hour".into()));
        let noisy = format!(r#"{{"type":"result","is_error":true,"api_error":"usage_limit_reached","result":"You've hit\nyour {}"}}"#, "x".repeat(400));
        let hit = parse_limit_result(noisy.as_bytes()).unwrap();
        assert!(hit.text.starts_with("You've hit your ") && hit.text.chars().count() == TEXT_MAX && hit.kind.is_none() && hit.http.is_none(), "{}", hit.text);
    }

    /// Never a limit: an answered result, B7's 401, a 429 throttle, an error
    /// result of another kind, garbage, another type.
    #[test]
    fn what_is_no_limit() {
        let answered = B16.lines().find(|l| l.contains("\"is_error\":false")).unwrap();
        for line in [
            answered,
            B7.trim_end(),
            r#"{"type":"result","is_error":true,"api_error":"rate_limit","api_error_status":429,"result":"API Error: 429 rate limited"}"#,
            r#"{"type":"result","is_error":true,"api_error_status":500,"result":"You've hit your weekly limit"}"#,
            r#"{"type":"result","is_error":false,"api_error":"usage_limit_reached","result":"You've hit your weekly limit"}"#,
            r#"{"type":"assistant","api_error":"usage_limit_reached","is_error":true}"#,
            "not json",
            "[1,2]",
        ] {
            assert_eq!(parse_limit_result(line.as_bytes()), None, "{line}");
        }
    }

    /// Every name maps to its kind; a text that names none (or is no limit's) gives none.
    #[test]
    fn every_limit_name_maps() {
        for (kind, name) in LIMIT_NAMES {
            assert_eq!(kind_of_text(&format!("You've hit your {name} · resets Fri 9am")), Some(kind), "{name}");
            assert_eq!(limit_words(kind), name);
            assert_ne!(kind_word(kind), kind, "{kind} has words");
        }
        assert_eq!(kind_of_text("You've hit your monthly cap"), None);
        assert_eq!(kind_of_text("weekly limit"), None);
        assert_eq!((limit_words("monthly"), kind_word("monthly")), ("usage limit", "monthly"));
        assert_eq!(reset_phrase("You've hit your weekly limit"), None);
    }

    /// The constructed events: the full one with both unified windows (and
    /// the top-level fields beside them), the rejected one with its type,
    /// utilization over 1 and reset; B16's trimmed event, its status alone.
    #[test]
    fn the_constructed_and_the_trimmed_events_parse() {
        let lines: Vec<&str> = CONSTRUCTED.lines().collect();
        assert_eq!(lines.len(), 2, "two constructed lines");
        let full = parse_event_line(lines[0].as_bytes()).expect("the full event");
        assert_eq!(full.status, Some("allowed_warning"));
        assert_eq!(full.five_hour, Some(Window { utilization: 0.23, resets_at: 1_792_591_200 }));
        assert_eq!(full.seven_day, Some(Window { utilization: 0.81, resets_at: 1_792_663_200 }));
        assert!(full.is_using_overage);
        assert_eq!(full.effective(), (full.five_hour, full.seven_day), "the unified windows win");
        let rejected = parse_event_line(lines[1].as_bytes()).expect("the rejected event");
        assert_eq!((rejected.status, rejected.rate_limit_type.as_deref(), rejected.utilization, rejected.resets_at), (Some("rejected"), Some("seven_day"), Some(1.02), Some(1_792_836_000)));
        assert_eq!(rejected.effective(), (None, Some(Window { utilization: 1.02, resets_at: 1_792_836_000 })), "the top level stands in for its type's window");
        let b16 = B16.lines().find(|l| l.contains("rate_limit_event")).unwrap();
        assert_eq!(parse_event_line(b16.as_bytes()), Some(RateLimitInfo { status: Some("allowed"), ..RateLimitInfo::default() }));
        assert_eq!(parse_event_line(b"{\"type\":\"result\"}"), None);
        assert_eq!(parse_event_line(b"{\"type\":\"rate_limit_event\"}"), None, "no info");
    }

    /// Wrong types read as absent; an integer utilization is one; an
    /// unknown status is none; a type other than the two windows' has no
    /// top-level window.
    #[test]
    fn wrong_types_read_as_absent() {
        let info = parse_info(r#"{"status":"maybe","resetsAt":"soon","utilization":1,"rateLimitType":"five_hour","unifiedWindows":{"five_hour":{"utilization":"x","resetsAt":5}},"isUsingOverage":"yes"}"#).unwrap();
        assert_eq!(info, RateLimitInfo { utilization: Some(1.0), rate_limit_type: Some("five_hour".into()), ..RateLimitInfo::default() });
        assert_eq!(info.effective(), (None, None), "no reset time: no window");
        let top = parse_info(r#"{"status":"allowed","utilization":0.5,"resetsAt":1792591200.9,"rateLimitType":"five_hour"}"#).unwrap();
        assert_eq!(top.effective(), (Some(Window { utilization: 0.5, resets_at: 1_792_591_200 }), None));
        let opus = parse_info(r#"{"status":"allowed","utilization":0.5,"resetsAt":1792591200,"rateLimitType":"seven_day_opus"}"#).unwrap();
        assert_eq!(opus.effective(), (None, None));
        assert_eq!(parse_info("[]"), None);
        assert_eq!(parse_info("garbage"), None);
    }

    /// `when` with a fixed now (Wed 2026-10-21 08:00Z) and `pct`.
    #[test]
    fn when_and_pct_read_as_shown() {
        assert_eq!(when(1_792_591_200, NOW), "14:00Z");
        assert_eq!(when(NOW + 20 * 3600 - 60, NOW), "03:59Z", "just within 20 hours");
        assert_eq!(when(1_792_663_200, NOW), "Thu 10:00Z");
        assert_eq!(when(1_792_836_000, NOW), "Sat 10:00Z");
        assert_eq!(when(1_793_613_600, NOW), "Nov 02 10:00Z");
        assert_eq!(when(NOW - 60, NOW), "07:59Z", "a time passed reads as a time of day");
        assert_eq!((pct(0.23), pct(0.814), pct(1.02), pct(0.0), pct(f64::NAN)), ("23%".to_string(), "81%".to_string(), "102%".to_string(), "0%".to_string(), "?%".to_string()));
    }
}
