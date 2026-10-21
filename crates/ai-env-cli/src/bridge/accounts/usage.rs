//! What ai-env saw of each Claude account's usage limits (S10 addendum A1,
//! plan §5): `[usage.<name>]` in `state/accounts.toml` ([`UsageRecord`]),
//! the rules an observation changes it by ([`apply`]), its writer
//! ([`record_all`]), the words `creds account list` and `check` show it in
//! ([`describe`]), the pump's tap ([`UsageTap`]) and the note a chat gets
//! when its account hit a limit ([`note_usage_limit`]).
//!
//! The store keeps each entry raw (L-3), so a malformed one never makes it
//! unreadable: [`read_record`] reads leniently (a field of the wrong type
//! is absent; an integer utilization is one). Times are unix seconds.
//!
//! ```toml
//! [usage.work]
//! seen_at = 1792569600          # the observation's time, not the write's
//! source = "chat"               # "chat" or "check"
//! status = "allowed_warning"    # allowed | allowed_warning | rejected
//! warning = "seven_day"         # an allowed_warning's rateLimitType
//! overage = true                # isUsingOverage
//! five_hour = { utilization = 0.23, resets_at = 1792584000 }
//! seven_day = { utilization = 0.81, resets_at = 1792836000 }
//! limited = { at = 1792569600, text = "You've hit your weekly limit · resets 10am (UTC)", kind = "seven_day", resets_at = 1792836000 }
//! ```
//!
//! An observation is attributed by the seal id of the token that made the
//! turn (`RemoteSnapshot.seal`, L-4): [`record_all`] names it by the store's
//! rows under the store's lock, and one no row holds writes nothing. The
//! pump never waits for the lock (`accounts::try_update`) and never creates
//! the store; a command does wait (`accounts::update`).
use super::{AccountsState, TryUpdate};
use crate::bridge::config::Paths;
use crate::wire::ratelimit::{kind_word, limit_words, pct, reset_phrase, when, LimitHit, RateLimitInfo, Window};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;

/// The pump writes what it saw at most this often, but for what is due at
/// once ([`UsageTap::offer`]).
pub const USAGE_WRITE_EVERY: Duration = Duration::from_secs(60);
/// A write the store's lock refused (`Busy`) is tried again this much later.
pub const USAGE_RETRY: Duration = Duration::from_secs(1);
/// A `limited` written this many seconds before a limit result (by the
/// turn's own `rejected` event) lends it its kind and reset.
pub const LIMIT_MERGE_S: u64 = 600;
/// [`UsageRecord::source`]'s words: a chat's turn, `creds account check`'s.
pub const SOURCE_CHAT: &str = "chat";
pub const SOURCE_CHECK: &str = "check";

/// One account's `[usage.<name>]`, every field optional.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UsageRecord {
    /// When the newest observation applied was made.
    pub seen_at: Option<u64>,
    /// [`SOURCE_CHAT`] or [`SOURCE_CHECK`].
    pub source: Option<String>,
    /// The last status a turn reported.
    pub status: Option<String>,
    /// The limit kind an `allowed_warning` named.
    pub warning: Option<String>,
    /// `isUsingOverage`, when said.
    pub overage: Option<bool>,
    pub five_hour: Option<Window>,
    pub seven_day: Option<Window>,
    pub limited: Option<LimitedRecord>,
}

/// The account hit a limit: when, the CLI's text (empty when only an event
/// said so), the limit's kind (`unknown` when nothing named it) and when it
/// resets, when known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitedRecord {
    pub at: u64,
    pub text: String,
    pub kind: String,
    pub resets_at: Option<u64>,
}

/// What a turn showed of an account's usage.
#[derive(Debug, Clone, PartialEq)]
pub enum Seen {
    /// A `rate_limit_event`'s info.
    Info(RateLimitInfo),
    /// A usage-limit result.
    Limited(LimitHit),
    /// An answered turn after a limit: the account answers again.
    Answered,
}

/// One observation, made at `at` (unix seconds).
#[derive(Debug, Clone, PartialEq)]
pub struct Observed {
    pub at: u64,
    pub what: Seen,
}

fn int(v: Option<&toml::Value>) -> Option<u64> {
    v?.as_integer().and_then(|i| u64::try_from(i).ok())
}

fn float(v: Option<&toml::Value>) -> Option<f64> {
    let v = v?;
    v.as_float().or_else(|| v.as_integer().map(|i| i as f64)).filter(|f| f.is_finite())
}

fn string(v: Option<&toml::Value>) -> Option<String> {
    v?.as_str().map(str::to_string)
}

fn window_of(v: Option<&toml::Value>) -> Option<Window> {
    let t = v?.as_table()?;
    Some(Window { utilization: float(t.get("utilization"))?, resets_at: int(t.get("resets_at"))? })
}

/// A raw `[usage.<name>]` entry read leniently: anything of the wrong type
/// reads as absent, a value that is no table as an empty record.
#[must_use]
pub fn read_record(v: &toml::Value) -> UsageRecord {
    let Some(t) = v.as_table() else { return UsageRecord::default() };
    let limited = t.get("limited").and_then(toml::Value::as_table).and_then(|l| {
        Some(LimitedRecord { at: int(l.get("at"))?, text: string(l.get("text")).unwrap_or_default(), kind: string(l.get("kind")).unwrap_or_else(|| "unknown".into()), resets_at: int(l.get("resets_at")) })
    });
    UsageRecord {
        seen_at: int(t.get("seen_at")),
        source: string(t.get("source")),
        status: string(t.get("status")),
        warning: string(t.get("warning")),
        overage: t.get("overage").and_then(toml::Value::as_bool),
        five_hour: window_of(t.get("five_hour")),
        seven_day: window_of(t.get("seven_day")),
        limited,
    }
}

fn integer(n: u64) -> toml::Value {
    toml::Value::Integer(i64::try_from(n).unwrap_or(i64::MAX))
}

fn window_value(w: &Window) -> toml::Value {
    toml::Value::Table(toml::map::Map::from_iter([("utilization".to_string(), toml::Value::Float(w.utilization)), ("resets_at".to_string(), integer(w.resets_at))]))
}

/// The record as its raw entry ([`read_record`] reads it back).
#[must_use]
pub fn to_value(rec: &UsageRecord) -> toml::Value {
    let mut t = toml::map::Map::new();
    let mut put = |k: &str, v: Option<toml::Value>| {
        if let Some(v) = v {
            t.insert(k.to_string(), v);
        }
    };
    put("seen_at", rec.seen_at.map(integer));
    put("source", rec.source.clone().map(toml::Value::String));
    put("status", rec.status.clone().map(toml::Value::String));
    put("warning", rec.warning.clone().map(toml::Value::String));
    put("overage", rec.overage.map(toml::Value::Boolean));
    put("five_hour", rec.five_hour.as_ref().map(window_value));
    put("seven_day", rec.seven_day.as_ref().map(window_value));
    put(
        "limited",
        rec.limited.as_ref().map(|l| {
            let mut m = toml::map::Map::from_iter([("at".to_string(), integer(l.at)), ("text".to_string(), toml::Value::String(l.text.clone())), ("kind".to_string(), toml::Value::String(l.kind.clone()))]);
            if let Some(r) = l.resets_at {
                m.insert("resets_at".to_string(), integer(r));
            }
            toml::Value::Table(m)
        }),
    );
    toml::Value::Table(t)
}

/// The longest a limit of `kind` lasts from when it was hit, for one whose
/// reset is not known (the CLI's result names none): a 5-hour window for
/// the session limit, else a week (the weekly ones, a usage credit's, one
/// of no known kind).
fn longest(kind: &str) -> u64 {
    if kind == "five_hour" {
        5 * 3600
    } else {
        7 * 86_400
    }
}

/// Is the limit still in force at `now`: its reset to come, or, none
/// known, hit within the longest its kind lasts ([`longest`]), so a limit
/// no turn or check saw again does not stand for ever.
fn in_force(l: &LimitedRecord, now: u64) -> bool {
    match l.resets_at {
        Some(r) => r > now,
        None => l.at.saturating_add(longest(&l.kind)) > now,
    }
}

/// `obs` applied to `rec` at `now`, from `source`:
/// - stored windows whose reset has passed are dropped first;
/// - an observation older than the record's is ignored (a late chat flush
///   never overwrites a fresher check);
/// - an event sets the status and whichever windows it carries (the top
///   level standing in for its type's, `RateLimitInfo::effective`);
///   `allowed` or `allowed_warning` clears `limited`; `rejected` sets it
///   (its type, else `unknown`; its reset), keeping a text already there;
/// - a limit result sets the status `rejected` and `limited` with the CLI's
///   text, its kind (the result's, else that of a `limited` written within
///   [`LIMIT_MERGE_S`] before it, else `unknown`) and its reset (the
///   result's, else that recent one's of the same kind);
/// - an answer clears `limited`, and a `rejected` status reads `allowed`.
pub fn apply(rec: &mut UsageRecord, obs: &Observed, source: &str, now: u64) {
    for w in [&mut rec.five_hour, &mut rec.seven_day] {
        if w.is_some_and(|w| w.resets_at <= now) {
            *w = None;
        }
    }
    if rec.seen_at.is_some_and(|seen| obs.at < seen) {
        return;
    }
    match &obs.what {
        Seen::Info(info) => {
            if let Some(status) = info.status {
                rec.status = Some(status.to_string());
                rec.warning = info.rate_limit_type.clone().filter(|_| status == "allowed_warning");
            }
            rec.overage = Some(info.is_using_overage);
            let (five, seven) = info.effective();
            let fresh = |w: Option<Window>| w.filter(|w| w.resets_at > now);
            if let Some(w) = fresh(five) {
                rec.five_hour = Some(w);
            }
            if let Some(w) = fresh(seven) {
                rec.seven_day = Some(w);
            }
            match info.status {
                Some("allowed" | "allowed_warning") => rec.limited = None,
                Some("rejected") => {
                    let kind = info.rate_limit_type.clone();
                    rec.limited = Some(match rec.limited.take() {
                        Some(l) => LimitedRecord { at: obs.at, kind: kind.unwrap_or(l.kind), resets_at: info.resets_at.or(l.resets_at), text: l.text },
                        None => LimitedRecord { at: obs.at, text: String::new(), kind: kind.unwrap_or_else(|| "unknown".into()), resets_at: info.resets_at },
                    });
                }
                _ => {}
            }
        }
        Seen::Limited(hit) => {
            rec.status = Some("rejected".to_string());
            rec.warning = None;
            let recent = rec.limited.as_ref().filter(|l| obs.at.saturating_sub(l.at) <= LIMIT_MERGE_S && l.kind != "unknown");
            let kind = hit.kind.clone().or_else(|| recent.map(|l| l.kind.clone())).unwrap_or_else(|| "unknown".into());
            let resets_at = hit.resets_at.or_else(|| recent.filter(|l| l.kind == kind).and_then(|l| l.resets_at));
            rec.limited = Some(LimitedRecord { at: obs.at, text: hit.text.clone(), kind, resets_at });
        }
        Seen::Answered => {
            rec.limited = None;
            if rec.status.as_deref() == Some("rejected") {
                rec.status = Some("allowed".to_string());
            }
        }
    }
    rec.seen_at = Some(rec.seen_at.map_or(obs.at, |seen| seen.max(obs.at)));
    rec.source = Some(source.to_string());
}

/// What [`record_all`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// A tag named an account, and its record changed: written.
    Written,
    /// A tag named an account; nothing changed.
    Unchanged,
    /// No tag names an account: nothing written.
    UnknownTag,
    /// There is no store, or no account in it: none created.
    NoStore,
    /// The pump's attempt found the store's lock held: nothing written.
    Busy,
    /// The store cannot be read, or its write failed (why): nothing written.
    Failed(String),
}

/// Apply each `(tag, observation)` of `items` (oldest first) to the record of
/// the account whose row has that seal, from `source`, in one write of
/// `state/accounts.toml` under its lock: `blocking` (a command) waits for
/// the lock ([`super::update`]), else (the pump) one try
/// ([`super::try_update`]). A tag no row names writes nothing; the store is
/// never created; usage of a name with no row is dropped with the write.
#[must_use]
pub fn record_all(paths: &Paths, items: &[(String, Observed)], source: &str, blocking: bool) -> Recorded {
    let now = crate::wire::time::unix_now();
    let mut ordered: Vec<&(String, Observed)> = items.iter().collect();
    ordered.sort_by_key(|(_, o)| o.at);
    // Whether a tag named an account, whether there was any account, whether the store changed.
    let mut seen = (false, false, false);
    let tried = {
        let write = |state: &mut AccountsState| {
            seen.1 = !state.account.is_empty();
            let before = state.clone();
            for (tag, obs) in &ordered {
                let Some(name) = state.account.iter().find(|r| r.tag == *tag && super::valid_name(&r.name)).map(|r| r.name.clone()) else { continue };
                seen.0 = true;
                let mut rec = state.usage.get(&name).map(read_record).unwrap_or_default();
                apply(&mut rec, obs, source, now);
                state.usage.insert(name, to_value(&rec));
            }
            if seen.0 {
                let names: Vec<String> = state.account.iter().map(|r| r.name.clone()).collect();
                state.usage.retain(|name, _| names.contains(name));
            }
            seen.2 = *state != before;
        };
        if blocking {
            super::update(paths, write).map(|()| TryUpdate::Unchanged)
        } else {
            super::try_update(paths, write)
        }
    };
    // A command's write says whether it changed the store through the flag.
    let tried = match tried {
        Ok(TryUpdate::Unchanged) if seen.2 => Ok(TryUpdate::Written),
        other => other,
    };
    match tried {
        Ok(TryUpdate::Written) => Recorded::Written,
        Ok(TryUpdate::Unchanged) if seen.0 => Recorded::Unchanged,
        Ok(TryUpdate::Unchanged) if seen.1 => Recorded::UnknownTag,
        Ok(TryUpdate::Unchanged | TryUpdate::NoFile) => Recorded::NoStore,
        Ok(TryUpdate::Busy) => Recorded::Busy,
        Ok(TryUpdate::Unreadable) => Recorded::Failed("state/accounts.toml cannot be read".into()),
        Err(e) => Recorded::Failed(e),
    }
}

/// How long before `now` `at` was, in a few words (`12 s`, `5 min`, `3 h`, `2 days`).
fn ago(at: u64, now: u64) -> String {
    let s = now.saturating_sub(at);
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 => format!("{} min", s / 60),
        3600..=172_799 => format!("{} h", s / 3600),
        _ => format!("{} days", s / 86_400),
    }
}

/// What the record says of the account's limits at `now`, for `creds
/// account check`'s line: a limit in force (`limited: weekly, "resets 10am
/// (UTC)" (Sat 10:00Z)`), else its windows (`5h 23% (resets 14:00Z), 7d 81%
/// (resets Thu 10:00Z)`; a window whose reset passed is gone), else `no
/// usage windows reported (status allowed)`; then `; near its weekly limit`
/// for an `allowed_warning`, `; using extra usage` with overage. `None` for
/// a record with nothing seen.
#[must_use]
pub fn standing(rec: &UsageRecord, now: u64) -> Option<String> {
    rec.seen_at?;
    let mut out = match rec.limited.as_ref().filter(|l| in_force(l, now)) {
        Some(l) => {
            let mut s = if l.kind == "unknown" { "limited".to_string() } else { format!("limited: {}", kind_word(&l.kind)) };
            let words = l.text.split_once(" · ").map_or(l.text.as_str(), |(_, w)| w);
            if !words.is_empty() {
                s.push_str(&format!(", {:?}", crate::bridge::remote::part(words, 80)));
            }
            if let Some(r) = l.resets_at {
                s.push_str(&format!(" ({})", when(r, now)));
            }
            s
        }
        None => {
            let shown: Vec<String> = [("5h", rec.five_hour), ("7d", rec.seven_day)].iter().filter_map(|(n, w)| w.filter(|w| w.resets_at > now).map(|w| format!("{n} {} (resets {})", pct(w.utilization), when(w.resets_at, now)))).collect();
            if shown.is_empty() {
                match &rec.status {
                    Some(s) => format!("no usage windows reported (status {s})"),
                    None => "no usage windows reported".to_string(),
                }
            } else {
                shown.join(", ")
            }
        }
    };
    if rec.status.as_deref() == Some("allowed_warning") {
        out.push_str(&format!("; near its {}", limit_words(rec.warning.as_deref().unwrap_or_default())));
    }
    if rec.overage == Some(true) {
        out.push_str("; using extra usage");
    }
    Some(out)
}

/// [`standing`], and when and how it was seen (`; seen 5 min ago in a
/// chat`): `creds account list`'s usage summary (`accounts::usage_summary`).
#[must_use]
pub fn describe(rec: &UsageRecord, now: u64) -> Option<String> {
    let body = standing(rec, now)?;
    let by = match rec.source.as_deref() {
        Some(SOURCE_CHECK) => " by a check",
        Some(SOURCE_CHAT) => " in a chat",
        _ => "",
    };
    Some(format!("{body}; seen {} ago{by}", ago(rec.seen_at.unwrap_or(now), now)))
}

/// Another account, as the note weighs it: limited (a limit in force), its
/// weekly use when known, and whether ai-env ever saw it.
#[derive(Debug, Clone, PartialEq)]
pub struct Standing {
    pub name: String,
    pub limited: bool,
    pub weekly: Option<f64>,
    pub seen: bool,
}

/// Every account of `state` but `except`, by name, as [`Standing`]s at `now`.
#[must_use]
pub fn others(state: &AccountsState, except: &str, now: u64) -> Vec<Standing> {
    state
        .account
        .iter()
        .filter(|r| r.name != except && super::valid_name(&r.name))
        .map(|r| {
            let rec = state.usage.get(&r.name).map(read_record).unwrap_or_default();
            let limited = rec.limited.as_ref().is_some_and(|l| in_force(l, now));
            Standing { name: r.name.clone(), limited, weekly: rec.seven_day.filter(|w| w.resets_at > now).map(|w| w.utilization), seen: rec.seen_at.is_some() }
        })
        .collect()
}

/// The note a chat gets after its account's usage-limit result (plan §5),
/// `account` the account whose token made the turn, `hit` the result, the
/// other accounts' `others`, `session` the chat's id (a move needs it), at
/// `now`. It says the limit and when it resets (`it resets Thu 10:00Z` when
/// the result names the time, else the CLI's own words, else nothing), then
/// one of: the account to switch to (a free one: the lowest weekly use
/// known, then one seen, then one never seen, which the note says), how
/// (`creds account use`, then reopen the chat, or `session migrate` it now);
/// that every other one is limited too; or that there is no other.
#[must_use]
pub fn note_usage_limit(account: &str, hit: &LimitHit, others: &[Standing], session: Option<&str>, now: u64) -> String {
    use crate::bridge::remote::part;
    let limit = limit_words(hit.kind.as_deref().unwrap_or_default());
    let resets = match (hit.resets_at, reset_phrase(&hit.text)) {
        (Some(at), _) => format!(" (it resets {})", when(at, now)),
        (None, Some(words)) => format!(" (it resets {})", part(words, 64)),
        (None, None) => String::new(),
    };
    let head = format!("ai-env: account {} hit its {limit}{resets}", part(account, 32));
    let mut free: Vec<&Standing> = others.iter().filter(|s| !s.limited).collect();
    // The lowest weekly use known first, then one seen with none known, then one never seen; by name among equals.
    free.sort_by(|a, b| {
        let rank = |s: &Standing| (s.weekly.is_none(), !s.seen, s.weekly.unwrap_or(0.0));
        let (ra, rb) = (rank(a), rank(b));
        (ra.0, ra.1).cmp(&(rb.0, rb.1)).then(ra.2.total_cmp(&rb.2)).then(a.name.cmp(&b.name))
    });
    match free.first() {
        None if others.is_empty() => format!("{head}; no other account to switch to: ai-env creds account add NAME seals one"),
        None => format!("{head}; every other account is limited too, as far as ai-env knows: ai-env creds account check measures them"),
        Some(pick) => {
            let name = part(&pick.name, 32);
            let unknown = if pick.seen { "" } else { " (its limits are unknown: ai-env creds account check)" };
            let then = match session {
                Some(sid) => format!("then reopen this chat or run ai-env session migrate {}", part(sid, 36)),
                None => "then reopen this chat".to_string(),
            };
            let more = if free.len() > 1 { "; ai-env creds account check shows every account's limits" } else { "" };
            format!("{head}; to go on now with account {name}{unknown}: ai-env creds account use {name}, {then}{more}")
        }
    }
}

/// The pump's usage tap (plan §5): what a remote chat's turns showed,
/// pending per seal id (at most one event and one limit or answer each, the
/// newer replacing the older), written at once when it is a limit, a
/// status change, the first thing seen, or the first answer after a limit
/// ([`UsageTap::take_limited`]), else at most every [`USAGE_WRITE_EVERY`];
/// a write the lock refused is due again [`USAGE_RETRY`] later. The pump
/// does the writing ([`record_all`], never waiting) and tells the tap its
/// outcome ([`UsageTap::after`]); the clock is the caller's. Counts for the
/// census: events seen, events written, limit results.
#[derive(Debug, Default)]
pub struct UsageTap {
    pending: BTreeMap<String, Slots>,
    due: Option<Instant>,
    written_at: Option<Instant>,
    /// The last status each seal reported.
    statuses: BTreeMap<String, &'static str>,
    /// The seals a limit result came for since their last answer.
    limits: Vec<String>,
    /// `rate_limit_event` lines seen, and those whose observation reached the store.
    pub seen: u32,
    pub written: u32,
    /// Usage-limit results.
    pub limited: u32,
}

/// One seal's pending observations.
#[derive(Debug, Default, Clone)]
struct Slots {
    info: Option<Observed>,
    verdict: Option<Observed>,
}

impl UsageTap {
    #[must_use]
    pub fn new() -> UsageTap {
        UsageTap::default()
    }

    /// `obs` made by a turn of seal `tag`, offered at `now`.
    pub fn offer(&mut self, tag: &str, obs: Observed, now: Instant) {
        let urgent = match &obs.what {
            Seen::Info(info) => {
                self.seen += 1;
                let last = self.statuses.get(tag).copied();
                if let Some(s) = info.status {
                    self.statuses.insert(tag.to_string(), s);
                }
                self.written_at.is_none() || info.status.is_some_and(|s| last != Some(s))
            }
            Seen::Limited(_) => {
                self.limited += 1;
                if !self.limits.iter().any(|t| t == tag) {
                    self.limits.push(tag.to_string());
                }
                true
            }
            Seen::Answered => true,
        };
        let slots = self.pending.entry(tag.to_string()).or_default();
        match obs.what {
            Seen::Info(_) => slots.info = Some(obs),
            _ => slots.verdict = Some(obs),
        }
        let later = self.written_at.map_or(now, |w| (w + USAGE_WRITE_EVERY).max(now));
        self.due = Some(match self.due {
            _ if urgent => now,
            Some(due) => due.min(later),
            None => later,
        });
    }

    /// Did seal `tag` hit a limit since its last answer? Then this answer is
    /// news, once: the limit is forgotten, so the turns after it are not
    /// (the next limit makes the next answer news again).
    pub fn take_limited(&mut self, tag: &str) -> bool {
        let before = self.limits.len();
        self.limits.retain(|t| t != tag);
        self.limits.len() != before
    }

    /// When the pending observations are due, if any are.
    #[must_use]
    pub fn due_at(&self) -> Option<Instant> {
        self.due.filter(|_| !self.pending.is_empty())
    }

    /// The pending observations, oldest first, once due at `now`.
    pub fn take_due(&mut self, now: Instant) -> Option<Vec<(String, Observed)>> {
        if self.due_at().is_some_and(|due| due <= now) {
            Some(self.take_pending())
        } else {
            None
        }
    }

    /// Every pending observation, oldest first, due or not (the close's flush).
    pub fn take_pending(&mut self) -> Vec<(String, Observed)> {
        self.due = None;
        let mut out: Vec<(String, Observed)> = std::mem::take(&mut self.pending).into_iter().flat_map(|(tag, s)| [s.info, s.verdict].into_iter().flatten().map(move |o| (tag.clone(), o))).collect();
        out.sort_by_key(|(_, o)| o.at);
        out
    }

    /// What became of `taken` (written at `now`): written, or found the
    /// store as it would be, counts its events and starts the throttle's
    /// interval; a lock held puts it back (what came meanwhile wins) and
    /// tries again [`USAGE_RETRY`] later; anything else drops it.
    pub fn after(&mut self, taken: Vec<(String, Observed)>, outcome: &Recorded, now: Instant) {
        match outcome {
            Recorded::Written | Recorded::Unchanged => {
                self.written_at = Some(now);
                self.written += u32::try_from(taken.iter().filter(|(_, o)| matches!(o.what, Seen::Info(_))).count()).unwrap_or(u32::MAX);
                if !self.pending.is_empty() {
                    self.due = Some(self.due.unwrap_or(now + USAGE_WRITE_EVERY));
                }
            }
            Recorded::Busy => {
                for (tag, obs) in taken {
                    let slots = self.pending.entry(tag).or_default();
                    let slot = if matches!(obs.what, Seen::Info(_)) { &mut slots.info } else { &mut slots.verdict };
                    if slot.is_none() {
                        *slot = Some(obs);
                    }
                }
                self.due = Some(now + USAGE_RETRY);
            }
            Recorded::UnknownTag | Recorded::NoStore | Recorded::Failed(_) => {
                if self.pending.is_empty() {
                    self.due = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::accounts::{read, update, AccountRow};
    use crate::wire::ratelimit::{parse_event_line, parse_info, parse_limit_result};

    /// Wed 2026-10-21 08:00Z.
    const NOW: u64 = 1_792_569_600;
    /// 14:00Z that day, Thu 10:00Z, Sat 10:00Z.
    const AT_14: u64 = 1_792_591_200;
    const THU_10: u64 = 1_792_663_200;
    const SAT_10: u64 = 1_792_836_000;
    const B2: &str = include_str!("../../../tests/fixtures/claude/usage-limit-result-2.1.305.json");
    const CONSTRUCTED: &str = include_str!("../../../tests/fixtures/claude/rate-limit-event-constructed-2.1.305.jsonl");

    fn info(text: &str) -> Seen {
        Seen::Info(parse_info(text).unwrap())
    }

    fn at(at: u64, what: Seen) -> Observed {
        Observed { at, what }
    }

    fn b2() -> LimitHit {
        parse_limit_result(B2.trim_end().as_bytes()).unwrap()
    }

    fn w(utilization: f64, resets_at: u64) -> Option<Window> {
        Some(Window { utilization, resets_at })
    }

    /// The constructed full event sets the status, both windows, the
    /// warning's kind and overage; the rejected one sets `limited` with its
    /// type and reset, keeping the windows; an `allowed` clears it.
    #[test]
    fn an_event_sets_the_status_and_its_windows() {
        let lines: Vec<&str> = CONSTRUCTED.lines().collect();
        let mut rec = UsageRecord::default();
        apply(&mut rec, &at(NOW, Seen::Info(parse_event_line(lines[0].as_bytes()).unwrap())), SOURCE_CHAT, NOW);
        assert_eq!(
            rec,
            UsageRecord { seen_at: Some(NOW), source: Some("chat".into()), status: Some("allowed_warning".into()), warning: Some("seven_day".into()), overage: Some(true), five_hour: w(0.23, AT_14), seven_day: w(0.81, THU_10), limited: None }
        );
        apply(&mut rec, &at(NOW + 10, Seen::Info(parse_event_line(lines[1].as_bytes()).unwrap())), SOURCE_CHAT, NOW);
        assert_eq!(rec.limited, Some(LimitedRecord { at: NOW + 10, text: String::new(), kind: "seven_day".into(), resets_at: Some(SAT_10) }));
        assert_eq!((rec.status.as_deref(), rec.seven_day, rec.five_hour), (Some("rejected"), w(1.02, SAT_10), w(0.23, AT_14)), "the top level stands in for the weekly window");
        apply(&mut rec, &at(NOW + 20, info(r#"{"status":"allowed"}"#)), SOURCE_CHAT, NOW);
        assert_eq!((rec.status.as_deref(), &rec.limited, &rec.warning), (Some("allowed"), &None, &None), "allowed clears the limit");
    }

    /// B2's result after its turn's `rejected` event: the text is the
    /// CLI's, the kind the text's, the reset the event's (the same kind,
    /// within the merge); with no event before it, no reset. An answer
    /// later clears it, and a status `rejected` reads `allowed`.
    #[test]
    fn a_limit_result_merges_with_its_events_reset_and_an_answer_clears_it() {
        let mut rec = UsageRecord::default();
        apply(&mut rec, &at(NOW, info(&format!(r#"{{"status":"rejected","rateLimitType":"seven_day","resetsAt":{SAT_10}}}"#))), SOURCE_CHAT, NOW);
        apply(&mut rec, &at(NOW + 1, Seen::Limited(b2())), SOURCE_CHAT, NOW);
        assert_eq!(rec.limited, Some(LimitedRecord { at: NOW + 1, text: "You've hit your weekly limit · resets 10am (UTC)".into(), kind: "seven_day".into(), resets_at: Some(SAT_10) }));
        assert_eq!(rec.status.as_deref(), Some("rejected"));
        // A rejected event after the result keeps its text.
        apply(&mut rec, &at(NOW + 2, info(r#"{"status":"rejected"}"#)), SOURCE_CHAT, NOW);
        assert_eq!(rec.limited.as_ref().map(|l| (l.text.as_str(), l.kind.as_str())), Some(("You've hit your weekly limit · resets 10am (UTC)", "seven_day")));
        let mut alone = UsageRecord::default();
        apply(&mut alone, &at(NOW, Seen::Limited(b2())), SOURCE_CHAT, NOW);
        assert_eq!(alone.limited.as_ref().map(|l| (l.kind.as_str(), l.resets_at)), Some(("seven_day", None)));
        // An event of another kind long before: no reset borrowed; a text naming nothing takes its kind only when recent.
        let mut old = UsageRecord::default();
        apply(&mut old, &at(NOW, info(&format!(r#"{{"status":"rejected","rateLimitType":"five_hour","resetsAt":{AT_14}}}"#))), SOURCE_CHAT, NOW);
        let nameless = LimitHit { text: "You've hit your limit".into(), kind: None, resets_at: None, http: Some(429), info: None };
        let mut later = old.clone();
        apply(&mut later, &at(NOW + LIMIT_MERGE_S + 1, Seen::Limited(nameless.clone())), SOURCE_CHAT, NOW);
        assert_eq!(later.limited.as_ref().map(|l| (l.kind.as_str(), l.resets_at)), Some(("unknown", None)));
        apply(&mut old, &at(NOW + 5, Seen::Limited(nameless)), SOURCE_CHAT, NOW);
        assert_eq!(old.limited.as_ref().map(|l| (l.kind.as_str(), l.resets_at)), Some(("five_hour", Some(AT_14))));
        apply(&mut rec, &at(NOW + 3, Seen::Answered), SOURCE_CHAT, NOW);
        assert_eq!((rec.limited, rec.status.as_deref()), (None, Some("allowed")));
    }

    /// An observation older than the record's is ignored (a late chat
    /// flush after a check); windows whose reset passed are dropped.
    #[test]
    fn stale_observations_are_ignored_and_passed_windows_dropped() {
        let mut rec = UsageRecord { seen_at: Some(NOW), source: Some("check".into()), status: Some("allowed".into()), five_hour: w(0.5, NOW - 1), seven_day: w(0.4, THU_10), ..UsageRecord::default() };
        apply(&mut rec, &at(NOW - 60, info(r#"{"status":"rejected","rateLimitType":"seven_day"}"#)), SOURCE_CHAT, NOW);
        assert_eq!((rec.status.as_deref(), rec.source.as_deref(), rec.limited.is_none(), rec.five_hour, rec.seven_day), (Some("allowed"), Some("check"), true, None, w(0.4, THU_10)), "stale: ignored; the passed window went");
        apply(&mut rec, &at(NOW + 1, info(&format!(r#"{{"status":"allowed","unifiedWindows":{{"five_hour":{{"utilization":0.9,"resetsAt":{}}}}}}}"#, NOW - 5))), SOURCE_CHAT, NOW);
        assert_eq!((rec.five_hour, rec.source.as_deref()), (None, Some("chat")), "a window already passed is never stored");
    }

    /// A record's raw entry reads back as itself; a malformed one leniently
    /// (wrong types absent, an integer utilization a fraction, no table an
    /// empty record).
    #[test]
    fn a_record_round_trips_and_reads_leniently() {
        let rec = UsageRecord {
            seen_at: Some(NOW),
            source: Some("chat".into()),
            status: Some("rejected".into()),
            warning: None,
            overage: Some(false),
            five_hour: w(0.23, AT_14),
            seven_day: w(1.02, SAT_10),
            limited: Some(LimitedRecord { at: NOW, text: "You've hit your weekly limit · resets 10am (UTC)".into(), kind: "seven_day".into(), resets_at: Some(SAT_10) }),
        };
        let v = to_value(&rec);
        assert_eq!(read_record(&v), rec);
        let text = toml::to_string(&v).unwrap();
        assert_eq!(read_record(&toml::from_str::<toml::Value>(&text).unwrap()), rec, "{text}");
        let odd: toml::Value = toml::from_str("seen_at = \"x\"\nsource = 5\nstatus = \"allowed\"\nfive_hour = { utilization = 1, resets_at = 1792591200 }\nseven_day = { utilization = \"a\", resets_at = 1 }\nlimited = { text = \"t\" }\noverage = \"yes\"\n").unwrap();
        assert_eq!(read_record(&odd), UsageRecord { status: Some("allowed".into()), five_hour: w(1.0, AT_14), ..UsageRecord::default() });
        assert_eq!(read_record(&toml::Value::Integer(5)), UsageRecord::default());
    }

    /// `standing` and `describe` as `check` and `list` show them, with a fixed now.
    #[test]
    fn the_standing_reads_as_shown() {
        let mut rec = UsageRecord { seen_at: Some(NOW - 300), source: Some("chat".into()), status: Some("allowed".into()), five_hour: w(0.23, AT_14), seven_day: w(0.81, THU_10), ..UsageRecord::default() };
        assert_eq!(standing(&rec, NOW).as_deref(), Some("5h 23% (resets 14:00Z), 7d 81% (resets Thu 10:00Z)"));
        assert_eq!(describe(&rec, NOW).as_deref(), Some("5h 23% (resets 14:00Z), 7d 81% (resets Thu 10:00Z); seen 5 min ago in a chat"));
        rec.status = Some("allowed_warning".into());
        rec.warning = Some("seven_day".into());
        rec.overage = Some(true);
        assert_eq!(standing(&rec, NOW).as_deref(), Some("5h 23% (resets 14:00Z), 7d 81% (resets Thu 10:00Z); near its weekly limit; using extra usage"));
        let mut limited = UsageRecord { seen_at: Some(NOW), source: Some("check".into()), status: Some("rejected".into()), ..UsageRecord::default() };
        apply(&mut limited, &at(NOW, Seen::Limited(b2())), SOURCE_CHECK, NOW);
        assert_eq!(standing(&limited, NOW).as_deref(), Some("limited: weekly, \"resets 10am (UTC)\""));
        assert_eq!(standing(&limited, NOW + 7 * 86_400 - 1).as_deref(), Some("limited: weekly, \"resets 10am (UTC)\""));
        assert_eq!(standing(&limited, NOW + 7 * 86_400).as_deref(), Some("no usage windows reported (status rejected)"), "no reset known: a week after it was hit, a weekly limit is no longer shown");
        limited.limited.as_mut().unwrap().resets_at = Some(SAT_10);
        assert_eq!(describe(&limited, NOW).as_deref(), Some("limited: weekly, \"resets 10am (UTC)\" (Sat 10:00Z); seen 0 s ago by a check"));
        assert_eq!(standing(&limited, SAT_10).as_deref(), Some("no usage windows reported (status rejected)"), "past its reset: the limit is no longer shown");
        let bare = UsageRecord { seen_at: Some(NOW - 7200), status: Some("allowed".into()), ..UsageRecord::default() };
        assert_eq!(describe(&bare, NOW).as_deref(), Some("no usage windows reported (status allowed); seen 2 h ago"));
        assert_eq!(describe(&UsageRecord::default(), NOW), None, "nothing seen");
        assert_eq!(crate::bridge::accounts::usage_summary(&to_value(&rec), NOW), describe(&rec, NOW), "the list's hook");
    }

    /// Every variant of the note, exactly: one free account (the fixture,
    /// a remote chat), every other limited, none other, several free (the
    /// lowest weekly use), a free one never seen, the reset time over the
    /// CLI's words, nothing known of it, no session id (no move offered).
    #[test]
    fn every_note_variant_reads_as_written() {
        let sid = "0a403528-1afc-4bdf-97a7-d9a67c42d89a";
        let free = |name: &str, weekly: Option<f64>| Standing { name: name.into(), limited: false, weekly, seen: true };
        let hit = b2();
        assert_eq!(
            note_usage_limit("work", &hit, &[free("spare", Some(0.2))], Some(sid), NOW),
            "ai-env: account work hit its weekly limit (it resets 10am (UTC)); to go on now with account spare: ai-env creds account use spare, then reopen this chat or run ai-env session migrate 0a403528-1afc-4bdf-97a7-d9a67c42d89a"
        );
        let limited = Standing { name: "spare".into(), limited: true, weekly: Some(1.0), seen: true };
        assert_eq!(
            note_usage_limit("work", &hit, &[limited], Some(sid), NOW),
            "ai-env: account work hit its weekly limit (it resets 10am (UTC)); every other account is limited too, as far as ai-env knows: ai-env creds account check measures them"
        );
        assert_eq!(note_usage_limit("work", &hit, &[], Some(sid), NOW), "ai-env: account work hit its weekly limit (it resets 10am (UTC)); no other account to switch to: ai-env creds account add NAME seals one");
        let several = [free("b", Some(0.7)), free("c", None), free("a", Some(0.3)), Standing { name: "d".into(), limited: false, weekly: None, seen: false }];
        assert_eq!(
            note_usage_limit("work", &hit, &several, Some(sid), NOW),
            "ai-env: account work hit its weekly limit (it resets 10am (UTC)); to go on now with account a: ai-env creds account use a, then reopen this chat or run ai-env session migrate 0a403528-1afc-4bdf-97a7-d9a67c42d89a; ai-env creds account check shows every account's limits"
        );
        let never = Standing { name: "spare".into(), limited: false, weekly: None, seen: false };
        let timed = LimitHit { resets_at: Some(THU_10), ..hit.clone() };
        assert_eq!(
            note_usage_limit("work", &timed, &[never], None, NOW),
            "ai-env: account work hit its weekly limit (it resets Thu 10:00Z); to go on now with account spare (its limits are unknown: ai-env creds account check): ai-env creds account use spare, then reopen this chat"
        );
        let bare = LimitHit { text: "You've hit your limit".into(), kind: None, resets_at: None, http: Some(429), info: None };
        assert_eq!(note_usage_limit("work", &bare, &[], None, NOW), "ai-env: account work hit its usage limit; no other account to switch to: ai-env creds account add NAME seals one");
    }

    /// The others' standing from a store: limited while in force, the
    /// weekly use when its window stands, seen or not; the account itself
    /// left out. A limit whose reset is not known (B2's result names none)
    /// stands for its kind's longest window from when it was hit (5 hours
    /// for the session limit, else a week), never for ever.
    #[test]
    fn the_others_standing_comes_from_the_store() {
        let row = |name: &str| AccountRow { name: name.into(), tag: format!("{name:0>16}"), ..AccountRow::default() };
        let names = ["work", "spare", "gone", "new", "week", "lastweek", "hour", "hours"];
        let mut state = AccountsState { active: Some("work".into()), account: names.iter().copied().map(row).collect(), usage: BTreeMap::new() };
        let limited = UsageRecord { seen_at: Some(NOW), limited: Some(LimitedRecord { at: NOW, text: String::new(), kind: "seven_day".into(), resets_at: Some(SAT_10) }), ..UsageRecord::default() };
        let passed = UsageRecord { seen_at: Some(NOW), limited: Some(LimitedRecord { at: NOW, text: String::new(), kind: "five_hour".into(), resets_at: Some(NOW - 1) }), seven_day: w(0.4, THU_10), ..UsageRecord::default() };
        let unreset = |kind: &str, ago: u64| UsageRecord { seen_at: Some(NOW - ago), limited: Some(LimitedRecord { at: NOW - ago, text: String::new(), kind: kind.into(), resets_at: None }), ..UsageRecord::default() };
        state.usage.insert("spare".into(), to_value(&limited));
        state.usage.insert("gone".into(), to_value(&passed));
        state.usage.insert("week".into(), to_value(&unreset("seven_day", 6 * 86_400)));
        state.usage.insert("lastweek".into(), to_value(&unreset("unknown", 7 * 86_400)));
        state.usage.insert("hour".into(), to_value(&unreset("five_hour", 4 * 3600)));
        state.usage.insert("hours".into(), to_value(&unreset("five_hour", 5 * 3600)));
        let got = others(&state, "work", NOW);
        let standing = |name: &str, limited: bool, weekly: Option<f64>, seen: bool| Standing { name: name.into(), limited, weekly, seen };
        assert_eq!(
            got,
            [
                standing("spare", true, None, true),
                standing("gone", false, Some(0.4), true),
                standing("new", false, None, false),
                standing("week", true, None, true),
                standing("lastweek", false, None, true),
                standing("hour", true, None, true),
                standing("hours", false, None, true),
            ]
        );
    }

    /// `record_all` names a tag by the store's rows, under its lock: an
    /// unknown tag leaves the file byte for byte, no store is never
    /// created, a usage entry of a name with no row goes with the write,
    /// and the pump's try is `Busy` at once while the lock is held.
    #[test]
    fn record_all_names_a_tag_by_its_row_and_never_creates_the_store() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let now = crate::wire::time::unix_now();
        let event = |s: &str| Observed { at: now, what: info(&format!(r#"{{"status":"{s}","unifiedWindows":{{"seven_day":{{"utilization":0.5,"resetsAt":{}}}}}}}"#, now + 3600)) };
        assert_eq!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), event("allowed"))], SOURCE_CHAT, false), Recorded::NoStore);
        assert_eq!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), event("allowed"))], SOURCE_CHAT, true), Recorded::NoStore);
        assert!(!paths.accounts_state().exists(), "never created");
        update(&paths, |s| {
            s.account = vec![AccountRow { name: "work".into(), tag: "aaaaaaaaaaaaaaaa".into(), ..AccountRow::default() }, AccountRow { name: "spare".into(), tag: "bbbbbbbbbbbbbbbb".into(), ..AccountRow::default() }];
            s.usage.insert("old".into(), toml::Value::Integer(1));
        })
        .unwrap();
        let before = std::fs::read(paths.accounts_state()).unwrap();
        assert_eq!(record_all(&paths, &[("cccccccccccccccc".into(), event("allowed"))], SOURCE_CHAT, false), Recorded::UnknownTag);
        assert_eq!(std::fs::read(paths.accounts_state()).unwrap(), before, "byte for byte");
        assert_eq!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), event("allowed"))], SOURCE_CHAT, false), Recorded::Written);
        let state = read(&paths).unwrap().unwrap();
        assert_eq!(state.usage.keys().collect::<Vec<_>>(), ["work"], "the row-less name's usage went");
        let rec = read_record(&state.usage["work"]);
        assert_eq!((rec.status.as_deref(), rec.source.as_deref(), rec.seven_day.map(|w| w.utilization)), (Some("allowed"), Some("chat"), Some(0.5)));
        assert_eq!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), event("allowed"))], SOURCE_CHAT, true), Recorded::Unchanged);
        let held = crate::bridge::accounts::lock(&paths).unwrap();
        let t = std::time::Instant::now();
        assert_eq!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), event("rejected"))], SOURCE_CHAT, false), Recorded::Busy);
        assert!(t.elapsed() < Duration::from_secs(1), "no wait");
        drop(held);
        // A limit and the answer after it, offered out of order: applied oldest first.
        let limit = Observed { at: now + 1, what: Seen::Limited(b2()) };
        let answer = Observed { at: now + 2, what: Seen::Answered };
        assert_eq!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), answer), ("aaaaaaaaaaaaaaaa".into(), limit)], SOURCE_CHAT, false), Recorded::Written);
        let rec = read_record(&read(&paths).unwrap().unwrap().usage["work"]);
        assert_eq!((rec.limited, rec.status.as_deref()), (None, Some("allowed")));
        std::fs::write(paths.accounts_state(), "[[account\n").unwrap();
        assert!(matches!(record_all(&paths, &[("aaaaaaaaaaaaaaaa".into(), event("allowed"))], SOURCE_CHAT, false), Recorded::Failed(_)));
    }

    /// Two writers at once never undo each other: each account's record is kept.
    #[test]
    fn two_writers_at_once_keep_both_records() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let names: Vec<String> = (0..8).map(|i| format!("acct{i}")).collect();
        update(&paths, |s| s.account = names.iter().enumerate().map(|(i, n)| AccountRow { name: n.clone(), tag: format!("{i:016x}"), ..AccountRow::default() }).collect()).unwrap();
        let now = crate::wire::time::unix_now();
        std::thread::scope(|s| {
            for i in 0..names.len() {
                let paths = &paths;
                s.spawn(move || {
                    let obs = Observed { at: now, what: info(r#"{"status":"allowed"}"#) };
                    assert_eq!(record_all(paths, &[(format!("{i:016x}"), obs)], SOURCE_CHECK, true), Recorded::Written);
                });
            }
        });
        let usage = read(&paths).unwrap().unwrap().usage;
        assert_eq!(usage.len(), names.len(), "every record kept: {usage:?}");
    }

    /// The tap with an injected clock: the first event is due at once; a
    /// second within the minute waits for it, a third replaces it; a status
    /// change is due at once; a limit at once, an answer after it at once;
    /// a busy store puts it all back and tries again a second later, what
    /// came meanwhile winning; the close takes what is pending, due or not.
    #[test]
    fn the_tap_throttles_and_writes_what_matters_at_once() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let allowed = |n: u64| Observed { at: NOW + n, what: info(r#"{"status":"allowed"}"#) };
        let mut tap = UsageTap::new();
        assert_eq!(tap.due_at(), None);
        tap.offer("a", allowed(0), t0);
        assert_eq!(tap.due_at(), Some(t0), "the first observation: at once");
        let taken = tap.take_due(t0).unwrap();
        assert_eq!(taken.len(), 1);
        tap.after(taken, &Recorded::Written, t0);
        assert_eq!((tap.seen, tap.written, tap.due_at()), (1, 1, None));
        tap.offer("a", allowed(10), t0 + s(10));
        assert_eq!(tap.due_at(), Some(t0 + USAGE_WRITE_EVERY), "throttled to the minute");
        assert!(tap.take_due(t0 + s(30)).is_none());
        tap.offer("a", allowed(20), t0 + s(20));
        assert_eq!(tap.due_at(), Some(t0 + USAGE_WRITE_EVERY));
        let taken = tap.take_due(t0 + USAGE_WRITE_EVERY).unwrap();
        assert_eq!(taken, [("a".to_string(), allowed(20))], "the newer replaced the older");
        tap.after(taken, &Recorded::Unchanged, t0 + USAGE_WRITE_EVERY);
        assert_eq!((tap.seen, tap.written), (3, 2));
        let t1 = t0 + s(70);
        tap.offer("a", Observed { at: NOW + 70, what: info(r#"{"status":"allowed_warning"}"#) }, t1);
        assert_eq!(tap.due_at(), Some(t1), "a status change: at once");
        let taken = tap.take_due(t1).unwrap();
        tap.after(taken.clone(), &Recorded::Busy, t1);
        assert_eq!(tap.due_at(), Some(t1 + USAGE_RETRY), "busy: again a second later");
        tap.offer("a", Observed { at: NOW + 71, what: Seen::Limited(b2()) }, t1 + s(1) / 2);
        assert_eq!((tap.due_at(), tap.limited), (Some(t1 + s(1) / 2), 1), "a limit: at once");
        let taken = tap.take_due(t1 + s(1)).unwrap();
        assert_eq!(taken.iter().map(|(_, o)| o.at).collect::<Vec<_>>(), [NOW + 70, NOW + 71], "the busy write put back, oldest first");
        tap.after(taken, &Recorded::Written, t1 + s(1));
        assert!(tap.take_limited("a") && !tap.take_limited("b"), "an answer after a's limit is news");
        tap.offer("a", Observed { at: NOW + 80, what: Seen::Answered }, t1 + s(10));
        assert_eq!(tap.due_at(), Some(t1 + s(10)), "an answer after the limit: at once");
        tap.offer("b", allowed(81), t1 + s(11));
        let rest = tap.take_pending();
        assert_eq!(rest.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(), ["a", "b"], "the close takes all, due or not");
        assert_eq!(tap.due_at(), None);
        tap.after(rest, &Recorded::UnknownTag, t1 + s(12));
        assert_eq!((tap.seen, tap.written, tap.limited), (5, 3, 1), "an unknown tag counts nothing written");
    }

    /// The first answer after a limit is news, once: the answers after it
    /// are not offered, so an event among them waits for its minute; the
    /// next limit makes its first answer news again.
    #[test]
    fn only_the_first_answer_after_a_limit_is_news() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let allowed = |n: u64| Observed { at: NOW + n, what: info(r#"{"status":"allowed"}"#) };
        let write = |tap: &mut UsageTap, now: Instant| {
            let taken = tap.take_due(now).expect("due");
            tap.after(taken, &Recorded::Written, now);
        };
        let mut tap = UsageTap::new();
        assert!(!tap.take_limited("a"), "no limit: an answer is no news");
        tap.offer("a", allowed(0), t0);
        write(&mut tap, t0);
        tap.offer("a", Observed { at: NOW + 1, what: Seen::Limited(b2()) }, t0 + s(1));
        write(&mut tap, t0 + s(1));
        assert!(tap.take_limited("a"), "the first answer after the limit");
        tap.offer("a", Observed { at: NOW + 2, what: Seen::Answered }, t0 + s(2));
        assert_eq!(tap.due_at(), Some(t0 + s(2)), "written at once");
        write(&mut tap, t0 + s(2));
        assert!(!tap.take_limited("a"), "the second answer is no news");
        tap.offer("a", allowed(3), t0 + s(3));
        assert_eq!(tap.due_at(), Some(t0 + s(2) + USAGE_WRITE_EVERY), "an event after it waits for its minute");
        tap.offer("a", Observed { at: NOW + 4, what: Seen::Limited(b2()) }, t0 + s(4));
        assert_eq!(tap.due_at(), Some(t0 + s(4)), "another limit: at once");
        assert!(tap.take_limited("a"), "its first answer is news again");
    }
}
