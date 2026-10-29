//! The three relay lists (WM-R7): `workers`, `token-signers` and `grants`, each a compact JSON array in one
//! SSM String parameter.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::globs::{glob_match, rule_match, valid_glob, valid_id, valid_rule};
use crate::keys::{Alg, PublicKey};

/// The lists' SSM prefix.
pub const PARAMETER_PREFIX: &str = "/ai-env/relay";
/// The workers' whitelist.
pub const WORKERS: &str = "/ai-env/relay/workers";
/// The grants.
pub const GRANTS: &str = "/ai-env/relay/grants";
/// The token signers.
pub const TOKEN_SIGNERS: &str = "/ai-env/relay/token-signers";
/// SSM's Standard limit.
pub const PARAMETER_MAX: usize = 4096;
/// The most entries of one list.
pub const ENTRIES_MAX: usize = 64;
/// The most source globs of one worker.
pub const SOURCES_MAX: usize = 16;
/// The most rules of one grant.
pub const RULES_MAX: usize = 32;

/// One whitelisted worker.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEntry {
    /// The worker's id.
    pub worker_id: String,
    /// `ed25519`.
    pub alg: String,
    /// The `b64` of its 32-byte key.
    pub public_key: String,
    /// The source globs it may register: 1 to 16.
    pub sources: Vec<String>,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub not_after: String,
}

/// One token signer (a Mac's session key).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerEntry {
    /// The signer's id (the token's `kid`).
    pub signer_id: String,
    /// `ed25519`.
    pub alg: String,
    /// The `b64` of its 32-byte key.
    pub public_key: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub not_after: String,
}

/// One grant: source and op rules.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The grant's id.
    pub grant_id: String,
    /// `<source-glob>/<op-glob>` rules: 1 to 32, sorted, no duplicate.
    pub allow: Vec<String>,
}

/// The workers list.
pub fn parse_workers(json: &str) -> Result<Vec<WorkerEntry>, PolicyError> {
    let list = parse_list("workers", json)?;
    check_workers(&list)?;
    Ok(list)
}

/// The token-signers list.
pub fn parse_signers(json: &str) -> Result<Vec<SignerEntry>, PolicyError> {
    let list = parse_list("token-signers", json)?;
    check_signers(&list)?;
    Ok(list)
}

/// The grants list.
pub fn parse_grants(json: &str) -> Result<Vec<Grant>, PolicyError> {
    let list = parse_list("grants", json)?;
    check_grants(&list)?;
    Ok(list)
}

/// Sorted by id, compact.
pub fn render_workers(list: &[WorkerEntry]) -> Result<String, PolicyError> {
    check_workers(list)?;
    let mut sorted = list.to_vec();
    sorted.sort_by(|a, b| a.worker_id.cmp(&b.worker_id));
    render("workers", &sorted)
}

/// Sorted by id, compact.
pub fn render_signers(list: &[SignerEntry]) -> Result<String, PolicyError> {
    check_signers(list)?;
    let mut sorted = list.to_vec();
    sorted.sort_by(|a, b| a.signer_id.cmp(&b.signer_id));
    render("token-signers", &sorted)
}

/// Sorted by id (each grant's rules sorted too), compact.
pub fn render_grants(list: &[Grant]) -> Result<String, PolicyError> {
    check_grants(list)?;
    let mut sorted = list.to_vec();
    sorted.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
    for grant in &mut sorted {
        grant.allow.sort();
    }
    render("grants", &sorted)
}

impl WorkerEntry {
    /// Its key (the entry parsed, so this cannot fail).
    pub fn key(&self) -> crate::keys::PublicKey {
        PublicKey::parse_b64(&self.public_key).expect("a worker entry from parse_workers holds a valid key")
    }

    /// `not_after` in unix seconds (0, never in force, if it does not parse).
    pub fn not_after_unix(&self) -> u64 {
        unix_of(&self.not_after).unwrap_or(0)
    }

    /// Whether one of its globs matches `source`.
    pub fn allows_source(&self, source: &str) -> bool {
        self.sources.iter().any(|glob| glob_match(glob, source))
    }
}

impl SignerEntry {
    /// Its key.
    pub fn key(&self) -> crate::keys::PublicKey {
        PublicKey::parse_b64(&self.public_key).expect("a signer entry from parse_signers holds a valid key")
    }

    /// `not_after` in unix seconds (0, never in force, if it does not parse).
    pub fn not_after_unix(&self) -> u64 {
        unix_of(&self.not_after).unwrap_or(0)
    }
}

impl Grant {
    /// Whether one of its rules matches `source` and `op`.
    pub fn allows(&self, source: &str, op: &str) -> bool {
        self.allow.iter().any(|rule| rule_match(rule, source, op))
    }
}

/// `YYYY-MM-DD` to `YYYY-MM-DDT23:59:59Z`. The error does not repeat the text: the caller names it.
pub fn not_after_of_day(day: &str) -> Result<String, PolicyError> {
    let b = day.as_bytes();
    let ok = b.len() == 10 && b[4] == b'-' && b[7] == b'-' && date_of(&b[..10]).is_some();
    if ok {
        Ok(format!("{day}T23:59:59Z"))
    } else {
        Err(PolicyError("not a day (YYYY-MM-DD)".to_string()))
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` to unix seconds. The error does not repeat the text: the caller names it.
pub fn unix_of(rfc3339: &str) -> Result<u64, PolicyError> {
    let bad = || PolicyError("not a UTC time (YYYY-MM-DDTHH:MM:SSZ)".to_string());
    let b = rfc3339.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return Err(bad());
    }
    let (y, m, d) = date_of(&b[..10]).ok_or_else(bad)?;
    let (hh, mm, ss) = (number(&b[11..13]).ok_or_else(bad)?, number(&b[14..16]).ok_or_else(bad)?, number(&b[17..19]).ok_or_else(bad)?);
    if hh > 23 || mm > 59 || ss > 59 {
        return Err(bad());
    }
    let days = days_from_civil(i64::from(y), m, d);
    u64::try_from(days * 86_400 + i64::from(hh * 3600 + mm * 60 + ss)).map_err(|_| bad())
}

/// `YYYY-MM-DD`'s year, month and day, when it is a real date from 1970.
fn date_of(b: &[u8]) -> Option<(u32, u32, u32)> {
    let (y, m, d) = (number(&b[0..4])?, number(&b[5..7])?, number(&b[8..10])?);
    (y >= 1970 && (1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m)).then_some((y, m, d))
}

/// ASCII digits only.
fn number(b: &[u8]) -> Option<u32> {
    b.iter().try_fold(0u32, |acc, &c| c.is_ascii_digit().then(|| acc * 10 + u32::from(c - b'0')))
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        2 if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day count since 1970-01-01 (H. Hinnant's `civil_from_days`).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A list's text: at most 4096 bytes, a JSON array of at most 64 entries, unknown fields refused.
fn parse_list<T: DeserializeOwned>(name: &str, json: &str) -> Result<Vec<T>, PolicyError> {
    if json.len() > PARAMETER_MAX {
        return Err(PolicyError(format!("{name}: {} bytes, over {PARAMETER_MAX}", json.len())));
    }
    // serde's own texts quote the values they met: only its position is kept.
    let items: Vec<serde_json::Value> =
        serde_json::from_str(json).map_err(|e| PolicyError(format!("{name}: not a JSON array (line {}, column {})", e.line(), e.column())))?;
    if items.len() > ENTRIES_MAX {
        return Err(PolicyError(format!("{name}: {} entries, over {ENTRIES_MAX}", items.len())));
    }
    items
        .into_iter()
        .enumerate()
        .map(|(i, item)| {
            if !item.is_object() {
                return Err(PolicyError(format!("{name}: entry {i}: not a JSON object")));
            }
            serde_json::from_value(item).map_err(|e| PolicyError(format!("{name}: entry {i}: {}", entry_failure(&e))))
        })
        .collect()
}

/// Why an entry did not type, in words of its own: serde's text quotes the values it met (and an unknown
/// field's name, which a list may hold anything in). A missing field is named: the name is the struct's.
fn entry_failure(e: &serde_json::Error) -> String {
    let text = e.to_string();
    if text.starts_with("unknown field") {
        "an unknown field".to_string()
    } else if let Some(field) = text.strip_prefix("missing field `").and_then(|rest| rest.split('`').next()) {
        format!("no {field}")
    } else {
        "a field of another type".to_string()
    }
}

/// The compact JSON of an already checked and sorted list, at most 4096 bytes.
fn render<T: Serialize>(name: &str, list: &[T]) -> Result<String, PolicyError> {
    let text = serde_json::to_string(list).map_err(|_| PolicyError(format!("{name}: does not render as JSON")))?;
    if text.len() > PARAMETER_MAX {
        return Err(PolicyError(format!("{name}: would be {} bytes, over {PARAMETER_MAX}", text.len())));
    }
    Ok(text)
}

/// The checks a key entry shares (its id, `alg`, key and `not_after`) for entry `i` of the list `name`; its
/// key's bytes back.
fn check_key_entry(name: &str, i: usize, id_field: &str, id: &str, alg: &str, key: &str, not_after: &str) -> Result<[u8; 32], PolicyError> {
    let bad = |why: String| PolicyError(format!("{name}: entry {i}: {why}"));
    if !valid_id(id) {
        return Err(bad(format!("{id_field} is not an id ({})", ai_env_source::names::NAME_RULE)));
    }
    if Alg::parse(alg).is_none() {
        return Err(bad("alg is not ed25519".to_string()));
    }
    let public = PublicKey::parse_b64(key).map_err(|e| bad(format!("public_key: {e}")))?;
    unix_of(not_after).map_err(|e| bad(format!("not_after: {e}")))?;
    Ok(*public.bytes())
}

/// No list holds more than 64 entries, an id twice or a key twice; a repeat names both entries.
fn unique<'a>(name: &str, id_field: &str, entries: impl Iterator<Item = (&'a str, Option<[u8; 32]>)>) -> Result<(), PolicyError> {
    let (mut ids, mut keys, mut n) = (HashMap::new(), HashMap::new(), 0usize);
    for (i, (id, key)) in entries.enumerate() {
        n += 1;
        if let Some(first) = ids.insert(id, i) {
            return Err(PolicyError(format!("{name}: entry {i}: {id_field} repeats entry {first}'s")));
        }
        if let Some(first) = key.and_then(|key| keys.insert(key, i)) {
            return Err(PolicyError(format!("{name}: entry {i}: public_key repeats entry {first}'s (one key, one id)")));
        }
    }
    if n > ENTRIES_MAX {
        return Err(PolicyError(format!("{name}: {n} entries, over {ENTRIES_MAX}")));
    }
    Ok(())
}

fn check_workers(list: &[WorkerEntry]) -> Result<(), PolicyError> {
    let mut checked = Vec::with_capacity(list.len());
    for (i, w) in list.iter().enumerate() {
        let key = check_key_entry("workers", i, "worker_id", &w.worker_id, &w.alg, &w.public_key, &w.not_after)?;
        if w.sources.is_empty() || w.sources.len() > SOURCES_MAX {
            return Err(PolicyError(format!("workers: entry {i}: {} source globs, not 1 to {SOURCES_MAX}", w.sources.len())));
        }
        if let Some(j) = w.sources.iter().position(|g| !valid_glob(g)) {
            return Err(PolicyError(format!("workers: entry {i}: sources[{j}] is not a source glob")));
        }
        checked.push((w.worker_id.as_str(), Some(key)));
    }
    unique("workers", "worker_id", checked.into_iter())
}

fn check_signers(list: &[SignerEntry]) -> Result<(), PolicyError> {
    let mut checked = Vec::with_capacity(list.len());
    for (i, s) in list.iter().enumerate() {
        let key = check_key_entry("token-signers", i, "signer_id", &s.signer_id, &s.alg, &s.public_key, &s.not_after)?;
        checked.push((s.signer_id.as_str(), Some(key)));
    }
    unique("token-signers", "signer_id", checked.into_iter())
}

fn check_grants(list: &[Grant]) -> Result<(), PolicyError> {
    for (i, g) in list.iter().enumerate() {
        if !valid_id(&g.grant_id) {
            return Err(PolicyError(format!("grants: entry {i}: grant_id is not an id ({})", ai_env_source::names::NAME_RULE)));
        }
        if g.allow.is_empty() || g.allow.len() > RULES_MAX {
            return Err(PolicyError(format!("grants: entry {i}: {} rules, not 1 to {RULES_MAX}", g.allow.len())));
        }
        if let Some(j) = g.allow.iter().position(|r| !valid_rule(r)) {
            return Err(PolicyError(format!("grants: entry {i}: allow[{j}] is not a rule (<source-glob>/<op-glob>)")));
        }
        let mut seen = HashMap::new();
        for (j, rule) in g.allow.iter().enumerate() {
            if let Some(first) = seen.insert(rule.as_str(), j) {
                return Err(PolicyError(format!("grants: entry {i}: allow[{j}] repeats allow[{first}]")));
            }
        }
    }
    unique("grants", "grant_id", list.iter().map(|g| (g.grant_id.as_str(), None)))
}

/// A list that does not parse or render (WM-R7): the relay and `ai-env relay` print its text. Phase 0 freezes
/// the name; W chooses its variants. The text names the list, an entry's index, a field and the reason, never
/// a value: the relay logs it (§R-relay.3.5), and the lists name private sources.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PolicyError(String);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    fn key_b64(seed: u8) -> String {
        SigningKey::from_seed(&[seed; 32]).expect("seed").public_key().b64()
    }

    fn worker(id: &str, seed: u8) -> WorkerEntry {
        WorkerEntry {
            worker_id: id.into(),
            alg: "ed25519".into(),
            public_key: key_b64(seed),
            sources: vec!["example-*".into()],
            not_after: "2027-10-29T23:59:59Z".into(),
        }
    }

    /// WM-T8.
    #[test]
    fn lists_render_sorted_compact_and_parse_back() {
        let list = vec![worker("worker-c", 3), worker("worker-a", 1), worker("worker-b", 2)];
        let text = render_workers(&list).expect("renders");
        let back = parse_workers(&text).expect("parses");
        let ids: Vec<&str> = back.iter().map(|w| w.worker_id.as_str()).collect();
        assert_eq!(ids, ["worker-a", "worker-b", "worker-c"]);
        assert!(!text.contains(' ') && !text.contains('\n'), "compact: {text}");
        assert!(text.starts_with(r#"[{"worker_id":"worker-a","alg":"ed25519","public_key":""#), "{text}");
        assert!(text.contains(r#"","sources":["example-*"],"not_after":"2027-10-29T23:59:59Z"}"#), "{text}");
        let mut sorted = list.clone();
        sorted.sort_by(|a, b| a.worker_id.cmp(&b.worker_id));
        assert_eq!(back, sorted);
        assert_eq!(parse_workers("[]").expect("empty"), vec![]);
        assert_eq!(render_workers(&[]).expect("empty"), "[]");

        let refused = |list: Vec<WorkerEntry>| render_workers(&list).is_err() && parse_workers(&serde_json::to_string(&list).expect("json")).is_err();
        assert!(refused(vec![worker("worker-a", 1), worker("worker-a", 2)]), "a duplicate id");
        assert!(refused(vec![worker("worker-a", 1), worker("worker-b", 1)]), "a key twice");
        let with = |f: &dyn Fn(&mut WorkerEntry)| {
            let mut w = worker("worker-a", 1);
            f(&mut w);
            vec![w]
        };
        assert!(refused(with(&|w| w.alg = "rsa".into())), "alg rsa");
        assert!(refused(with(&|w| w.public_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 31]))), "a 31-byte key");
        assert!(refused(with(&|w| w.not_after = "2027-13-01T00:00:00Z".into())), "month 13");
        assert!(refused(with(&|w| w.sources = (0..17).map(|i| format!("s{i}-*")).collect())), "17 source globs");
        assert!(refused(with(&|w| w.sources = vec![])), "no source glob");
        assert!(refused(with(&|w| w.sources = vec!["A*".into()])), "a bad glob");
        assert!(refused(with(&|w| w.worker_id = "A".into())), "a bad id");
        let unknown = text.replacen(r#""alg""#, r#""extra":1,"alg""#, 1);
        assert_eq!(parse_workers(&unknown).expect_err("an unknown field").to_string(), "workers: entry 0: an unknown field");

        // A text names the list, the entry, the field and the reason, never a value: the relay logs it.
        let planted = "zz-planted";
        let good = serde_json::to_value(worker("worker-a", 1)).expect("json");
        let with = |field: &str, value: serde_json::Value| {
            let mut entry = good.clone();
            entry[field] = value;
            serde_json::to_string(&[entry]).expect("json")
        };
        let mut twice = good.clone();
        twice["worker_id"] = serde_json::json!(planted);
        let mut no_alg = good.clone();
        no_alg.as_object_mut().expect("an object").remove("alg");
        let not_an_id = format!("workers: entry 0: worker_id is not an id ({})", ai_env_source::names::NAME_RULE);
        let workers = [
            (with("worker_id", serde_json::json!(planted.to_uppercase())), not_an_id.as_str()),
            (with("alg", serde_json::json!(planted)), "workers: entry 0: alg is not ed25519"),
            (with("public_key", serde_json::json!(planted)), "workers: entry 0: public_key: a public key is the standard base64 (with padding) of 32 bytes"),
            (with("sources", serde_json::json!([format!("{planted}/x")])), "workers: entry 0: sources[0] is not a source glob"),
            (with("sources", serde_json::json!(planted)), "workers: entry 0: a field of another type"),
            (with("not_after", serde_json::json!(planted)), "workers: entry 0: not_after: not a UTC time (YYYY-MM-DDTHH:MM:SSZ)"),
            (with(planted, serde_json::json!(1)), "workers: entry 0: an unknown field"),
            (format!("[{no_alg}]"), "workers: entry 0: no alg"),
            (format!("[{}]", [twice.to_string(), twice.to_string()].join(",")), "workers: entry 1: worker_id repeats entry 0's"),
            (format!("[{planted}]"), "workers: not a JSON array (line 1, column 2)"),
            (format!("{:?}", planted), "workers: not a JSON array (line 1, column 12)"),
            (r#"[1]"#.to_string(), "workers: entry 0: not a JSON object"),
        ];
        for (list, want) in workers {
            assert_eq!(parse_workers(&list).expect_err("refused").to_string(), want, "{list}");
        }
        let rules = |allow: serde_json::Value| serde_json::json!([{ "grant_id": planted, "allow": allow }]).to_string();
        let texts = [
            parse_grants(&rules(serde_json::json!([planted]))).expect_err("not a rule").to_string(),
            parse_grants(&rules(serde_json::json!([format!("{planted}/get"), format!("{planted}/get")]))).expect_err("twice").to_string(),
            unix_of(planted).expect_err("not a time").to_string(),
            not_after_of_day(planted).expect_err("not a day").to_string(),
        ];
        assert_eq!(texts[..2], ["grants: entry 0: allow[0] is not a rule (<source-glob>/<op-glob>)", "grants: entry 0: allow[1] repeats allow[0]"]);
        assert!(texts.iter().all(|t| !t.to_lowercase().contains(planted)), "{texts:?}");

        let grant = |id: &str, n: usize| Grant { grant_id: id.into(), allow: (0..n).map(|i| format!("example-{i:02}/get")).collect() };
        assert!(render_grants(&[grant("default", 33)]).is_err(), "33 rules");
        assert!(parse_grants(&serde_json::to_string(&[grant("default", 33)]).expect("json")).is_err());
        let one = Grant { grant_id: "default".into(), allow: vec!["a".into()] };
        assert!(render_grants(std::slice::from_ref(&one)).is_err(), "a rule `a`");
        assert!(parse_grants(r#"[{"grant_id":"default","allow":["a"]}]"#).is_err());
        assert!(parse_grants(r#"[{"grant_id":"default","allow":["a/b","a/b"]}]"#).is_err(), "a rule twice");
        let g = Grant { grant_id: "default".into(), allow: vec!["example-*/list".into(), "example-*/get".into()] };
        let rendered = render_grants(std::slice::from_ref(&g)).expect("renders");
        assert_eq!(rendered, r#"[{"grant_id":"default","allow":["example-*/get","example-*/list"]}]"#);
        assert_eq!(parse_grants(&rendered).expect("parses")[0].allow, ["example-*/get", "example-*/list"]);

        let many: Vec<WorkerEntry> = (0..65).map(|i| worker(&format!("w{i:02}"), i)).collect();
        assert_eq!(render_workers(&many).expect_err("65 entries").to_string(), "workers: 65 entries, over 64");
        let wide: Vec<WorkerEntry> = (0..40).map(|i| worker(&format!("worker-{i:02}"), i)).collect();
        assert!(render_workers(&wide).expect_err("over 4096 bytes").to_string().contains("over 4096"));
        let e = parse_workers(&format!("{}{}", "[]", " ".repeat(4095))).expect_err("4097 bytes");
        assert_eq!(e.to_string(), "workers: 4097 bytes, over 4096");
        let entries = format!("[{}]", vec!["{}"; 65].join(","));
        assert_eq!(parse_workers(&entries).expect_err("65 entries").to_string(), "workers: 65 entries, over 64");
        let small = serde_json::to_string(&(0..65).map(|i| Grant { grant_id: format!("g{i}"), allow: vec!["*/*".into()] }).collect::<Vec<_>>()).expect("json");
        assert!(small.len() <= 4096, "{}", small.len());
        assert_eq!(parse_grants(&small).expect_err("65 entries").to_string(), "grants: 65 entries, over 64");

        assert_eq!(not_after_of_day("2027-10-29").expect("a day"), "2027-10-29T23:59:59Z");
        assert_eq!(unix_of("2027-10-29T23:59:59Z"), Ok(1_824_854_399));
        assert_eq!(unix_of("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(unix_of("2028-02-29T00:00:00Z"), Ok(1_835_395_200));
        for bad in ["2027-02-29T00:00:00Z", "2027-10-29 23:59:59Z", "2027-10-29T24:00:00Z", "2027-10-29T23:59:59", "1969-12-31T23:59:59Z"] {
            assert!(unix_of(bad).is_err(), "{bad}");
        }
        for bad in ["2027-13-01", "2027-1-01", "27-10-29", "2027-10-32"] {
            assert!(not_after_of_day(bad).is_err(), "{bad}");
        }
        assert_eq!(worker("worker-a", 1).not_after_unix(), 1_824_854_399);
        assert_eq!(worker("worker-a", 1).key(), SigningKey::from_seed(&[1; 32]).expect("seed").public_key());

        let rules = ["example-*/get", "*/list"];
        let g = Grant { grant_id: "default".into(), allow: rules.iter().map(|r| r.to_string()).collect() };
        for (source, op) in [("example-a", "get"), ("example-a", "put"), ("other", "list"), ("other", "get")] {
            assert_eq!(g.allows(source, op), rules.iter().any(|r| rule_match(r, source, op)), "{source}/{op}");
        }
        let w = WorkerEntry { sources: vec!["example-*".into(), "logs".into()], ..worker("worker-a", 1) };
        for source in ["example-a", "logs", "logs-b", "other"] {
            assert_eq!(w.allows_source(source), w.sources.iter().any(|g| glob_match(g, source)), "{source}");
        }
        for (days, date) in [(0, (1970, 1, 1)), (19_843, (2024, 4, 30)), (-1, (1969, 12, 31)), (11_016, (2000, 2, 29))] {
            assert_eq!(civil_from_days(days), date);
            assert_eq!(days_from_civil(date.0, date.1, date.2), days);
        }
    }
}
