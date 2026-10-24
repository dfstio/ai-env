//! What a Claude account's turns say of its usage limits (S10 addendum A1):
//! claude's `rate_limit_event` line and its usage-limit `result`, read
//! leniently, and the words ai-env shows them in. Pure and serde-only, as
//! [`super::claude`]: the pump's usage tap (`bridge::accounts::usage`) and
//! `creds account check` use them.
//!
//! Shapes (claude 2.1.305, read from its bundle as data; S10's A1 check
//! recorded two real events of 2.1.306, 21 Oct 2026:
//! `tests/fixtures/claude/rate-limit-event-2.1.306.jsonl`):
//! * `{"type":"rate_limit_event","rate_limit_info":{…},"uuid":…,"session_id":…}`,
//!   one per real turn. Its `rate_limit_info`: `status` (`allowed`,
//!   `allowed_warning`, `rejected`), and optionally `resetsAt` (unix
//!   seconds; S11 reads milliseconds and RFC 3339 too, L9), `rateLimitType`
//!   (a kind of [`LIMIT_NAMES`]), `utilization` (a fraction),
//!   `unifiedWindows` (`five_hour`, `seven_day`, each `{utilization,
//!   resetsAt}`), `overageStatus`, `isUsingOverage`, `surpassedThreshold`
//!   and more. S7's B16 (2.1.296) printed `status` alone.
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
pub const HIT: &str = "You've hit your ";
/// What comes before the reset phrase in it.
pub const RESETS: &str = " · resets ";

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
/// `rateLimitType`, else the text's name, [`kind_of_text`]; else, through
/// [`LimitHit::or_event`], the turn's `rejected` event's), when it resets
/// when the params say (else that event's, for a limit of its kind), the
/// HTTP status, and the params' info.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitHit {
    pub text: String,
    pub kind: Option<String>,
    pub resets_at: Option<u64>,
    pub http: Option<u16>,
    pub info: Option<RateLimitInfo>,
}

/// A time as claude gives it (S11, L9: the check's rule joins the tap's):
/// unix seconds as an integer or a float (truncated); a number past 10^12
/// is milliseconds (divided by 1000); an RFC 3339 string
/// (`wire::time::parse_rfc3339_utc`); anything else none.
fn seconds(v: Option<&Value>) -> Option<u64> {
    let n = match v? {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f as u64))?,
        Value::String(s) => return super::time::parse_rfc3339_utc(s),
        _ => return None,
    };
    Some(if n > 1_000_000_000_000 { n / 1000 } else { n })
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

impl LimitHit {
    /// S11 (L9): the turn's own event, when its status is `rejected`, lends a
    /// limit result its `rateLimitType` as `kind` where the result has none,
    /// then its `resetsAt` as `resets_at` where the result has none and the
    /// kind, its own or lent, is the event's (a reset of another kind, or of
    /// none named, is not this limit's: `accounts::usage::apply`'s merge, the
    /// tap's); any other event, or none, lends nothing.
    #[must_use]
    pub fn or_event(mut self, event: Option<&RateLimitInfo>) -> LimitHit {
        if let Some(e) = event.filter(|e| e.status == Some("rejected")) {
            if self.kind.is_none() {
                self.kind.clone_from(&e.rate_limit_type);
            }
            if self.resets_at.is_none() && self.kind.is_some() && self.kind == e.rate_limit_type {
                self.resets_at = e.resets_at;
            }
        }
        self
    }
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

/// A fraction as a whole percentage (`0.23`: `23%`; it may pass 100); a
/// negative one, or none, `?%`.
#[must_use]
pub fn pct(utilization: f64) -> String {
    let p = (utilization * 100.0).round();
    if p.is_finite() && utilization >= 0.0 {
        format!("{:.0}%", p.abs())
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
    /// The real events of 2.1.306 (A1's check, 21 Oct 2026): an `allowed`
    /// one with both unified windows, a `rejected` one with both.
    const REAL: &str = include_str!("../../tests/fixtures/claude/rate-limit-event-2.1.306.jsonl");
    /// The two shapes no real line has shown yet (built from 2.1.305's
    /// schema, S10): an `allowed_warning` with both windows beside the top
    /// level, and a `rejected` one with no windows.
    const WARNING: &str = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1792663200,"rateLimitType":"seven_day","utilization":0.81,"unifiedWindows":{"five_hour":{"utilization":0.23,"resetsAt":1792591200},"seven_day":{"utilization":0.81,"resetsAt":1792663200}},"overageStatus":"allowed","isUsingOverage":true,"surpassedThreshold":0.75},"uuid":"00000000-0000-4000-8000-000000000001","session_id":"00000000-0000-4000-8000-0000000000a1"}"#;
    const WINDOWLESS: &str = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1792836000,"rateLimitType":"seven_day","utilization":1.02,"overageStatus":"rejected","isUsingOverage":false},"uuid":"00000000-0000-4000-8000-000000000002","session_id":"00000000-0000-4000-8000-0000000000a1"}"#;
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

    /// The real events of 2.1.306: the `allowed` one with both unified
    /// windows (an integer 0 utilization among them) beside its top-level
    /// type and reset, the `rejected` weekly one with both; then the two
    /// shapes inline: the warning with both windows (and the top-level
    /// fields beside them), the windowless rejection with its type,
    /// utilization over 1 and reset; B16's trimmed event, its status alone.
    #[test]
    fn the_real_2_1_306_events_parse() {
        assert!(REAL.ends_with("}\n") && !REAL.contains("sk-ant-"), "whole lines, no token");
        let lines: Vec<&str> = REAL.lines().collect();
        assert_eq!(lines.len(), 2, "two real lines");
        let allowed = parse_event_line(lines[0].as_bytes()).expect("the allowed event");
        let both = |five: (f64, u64), seven: (f64, u64)| (Some(Window { utilization: five.0, resets_at: five.1 }), Some(Window { utilization: seven.0, resets_at: seven.1 }));
        let (five_hour, seven_day) = both((0.02, 1_792_618_200), (0.0, 1_792_839_600));
        assert_eq!(allowed, RateLimitInfo { status: Some("allowed"), resets_at: Some(1_792_618_200), rate_limit_type: Some("five_hour".into()), utilization: None, five_hour, seven_day, is_using_overage: false });
        assert_eq!(allowed.effective(), (five_hour, seven_day));
        let rejected = parse_event_line(lines[1].as_bytes()).expect("the rejected event");
        let (five_hour, seven_day) = both((0.0, 1_792_627_800), (1.0, 1_792_663_200));
        assert_eq!(rejected, RateLimitInfo { status: Some("rejected"), resets_at: Some(1_792_663_200), rate_limit_type: Some("seven_day".into()), utilization: None, five_hour, seven_day, is_using_overage: false });
        assert_eq!([1_792_618_200, 1_792_839_600, 1_792_627_800, 1_792_663_200].map(|at| when(at, NOW)), ["21:30Z", "Sat 11:00Z", "00:10Z", "Thu 10:00Z"]);
        let full = parse_event_line(WARNING.as_bytes()).expect("the full event");
        assert_eq!(full.status, Some("allowed_warning"));
        assert_eq!(full.five_hour, Some(Window { utilization: 0.23, resets_at: 1_792_591_200 }));
        assert_eq!(full.seven_day, Some(Window { utilization: 0.81, resets_at: 1_792_663_200 }));
        assert!(full.is_using_overage);
        assert_eq!(full.effective(), (full.five_hour, full.seven_day), "the unified windows win");
        let rejected = parse_event_line(WINDOWLESS.as_bytes()).expect("the windowless event");
        assert_eq!((rejected.status, rejected.rate_limit_type.as_deref(), rejected.utilization, rejected.resets_at), (Some("rejected"), Some("seven_day"), Some(1.02), Some(1_792_836_000)));
        assert_eq!(rejected.effective(), (None, Some(Window { utilization: 1.02, resets_at: 1_792_836_000 })), "the top level stands in for its type's window");
        let b16 = B16.lines().find(|l| l.contains("rate_limit_event")).unwrap();
        assert_eq!(parse_event_line(b16.as_bytes()), Some(RateLimitInfo { status: Some("allowed"), ..RateLimitInfo::default() }));
        assert_eq!(parse_event_line(b"{\"type\":\"result\"}"), None);
        assert_eq!(parse_event_line(b"{\"type\":\"rate_limit_event\"}"), None, "no info");
    }

    /// Every time an event or a result gives goes through `seconds` (L9):
    /// an integer, a float truncated, a number past 10^12 as milliseconds,
    /// an RFC 3339 string (UTC); anything else none.
    #[test]
    fn seconds_read_milliseconds_and_rfc3339() {
        let s = |text: &str| seconds(Some(&serde_json::from_str::<Value>(text).unwrap()));
        assert_eq!(s("1792591200"), Some(1_792_591_200));
        assert_eq!(s("1792591200.9"), Some(1_792_591_200), "truncated");
        assert_eq!(s("1792591200000"), Some(1_792_591_200), "milliseconds");
        assert_eq!(s("1792591200999.5"), Some(1_792_591_200), "milliseconds, a float");
        assert_eq!(s("1000000000000"), Some(1_000_000_000_000), "10^12 itself is seconds");
        assert_eq!(s(r#""2026-10-21T14:00:00Z""#), Some(1_792_591_200));
        assert_eq!(s(r#""2026-10-21T14:00:00.250Z""#), Some(1_792_591_200));
        for none in [r#""soon""#, r#""2026-10-21T14:00:00+02:00""#, r#""1792591200""#, "-5", "true", "null", "[1792591200]", "{}"] {
            assert_eq!(s(none), None, "{none}");
        }
        assert_eq!(seconds(None), None);
        // Through the parsers: the top level's reset, a window's, a result's params'.
        let info = parse_info(r#"{"status":"rejected","resetsAt":"2026-10-24T10:00:00Z","rateLimitType":"seven_day","unifiedWindows":{"five_hour":{"utilization":0.1,"resetsAt":1792591200000}}}"#).unwrap();
        assert_eq!((info.resets_at, info.five_hour), (Some(1_792_836_000), Some(Window { utilization: 0.1, resets_at: 1_792_591_200 })));
        let hit = parse_limit_result(br#"{"type":"result","is_error":true,"api_error":"usage_limit_reached","result":"You've hit your weekly limit","api_error_params":{"rate_limit_info":{"resetsAt":1792836000000}}}"#).unwrap();
        assert_eq!((hit.kind.as_deref(), hit.resets_at), (Some("seven_day"), Some(1_792_836_000)));
    }

    /// `or_event` (L9): the turn's `rejected` event lends a limit its type
    /// and its reset where the result has none, never over the result's
    /// own, the reset only to a limit of the event's kind; an `allowed` or
    /// `allowed_warning` event, one with no status, or none lends nothing.
    #[test]
    fn or_event_lends_only_a_rejected_events_kind_and_reset() {
        let rejected = parse_event_line(REAL.lines().nth(1).unwrap().as_bytes()).unwrap();
        let bare = LimitHit { text: "You've hit your limit".into(), kind: None, resets_at: None, http: Some(429), info: None };
        assert_eq!(bare.clone().or_event(Some(&rejected)), LimitHit { kind: Some("seven_day".into()), resets_at: Some(1_792_663_200), ..bare.clone() }, "the kind and the reset, nothing else");
        // B2's text names its kind: only the reset is lent.
        let b2 = parse_limit_result(B2.trim_end().as_bytes()).unwrap();
        assert_eq!(b2.clone().or_event(Some(&rejected)), LimitHit { resets_at: Some(1_792_663_200), ..b2.clone() });
        // The params' own kind and reset stand.
        let own = LimitHit { kind: Some("seven_day_opus".into()), resets_at: Some(1_792_836_000), ..bare.clone() };
        assert_eq!(own.clone().or_event(Some(&rejected)), own);
        // An Opus limit with no reset: the weekly event's reset is not its (usage::apply's merge).
        let opus = LimitHit { kind: Some("seven_day_opus".into()), ..bare.clone() };
        assert_eq!(opus.clone().or_event(Some(&rejected)).resets_at, None);
        assert_eq!(opus.clone().or_event(Some(&rejected)), opus);
        // A rejected event that names no kind lends nothing: no kind, and its reset is no kind's.
        let typeless = RateLimitInfo { rate_limit_type: None, ..rejected.clone() };
        assert_eq!(bare.clone().or_event(Some(&typeless)), bare);
        let allowed = parse_event_line(REAL.lines().next().unwrap().as_bytes()).unwrap();
        let warning = parse_event_line(WARNING.as_bytes()).unwrap();
        let no_status = RateLimitInfo { rate_limit_type: Some("seven_day".into()), resets_at: Some(1_792_663_200), ..RateLimitInfo::default() };
        for event in [Some(&allowed), Some(&warning), Some(&no_status), None] {
            assert_eq!(bare.clone().or_event(event), bare, "{event:?}");
            assert_eq!(b2.clone().or_event(event), b2, "{event:?}");
        }
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
        // The bounds are open (L9: the check's `<=` gave `HH:MMZ` and `Ddd HH:MMZ` here).
        assert_eq!(when(NOW + 20 * 3600, NOW), "Thu 04:00Z", "20 hours ahead exactly");
        assert_eq!(when(NOW + 6 * 86_400, NOW), "Oct 27 08:00Z", "6 days ahead exactly");
        assert_eq!((pct(0.23), pct(0.814), pct(1.02), pct(0.0), pct(f64::NAN)), ("23%".to_string(), "81%".to_string(), "102%".to_string(), "0%".to_string(), "?%".to_string()));
        assert_eq!((pct(-0.1), pct(-0.001), pct(-0.0), pct(1.0), pct(f64::INFINITY)), ("?%".to_string(), "?%".to_string(), "0%".to_string(), "100%".to_string(), "?%".to_string()), "a negative one is no percentage (L9)");
    }
}
