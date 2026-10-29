//! S12 (T): a chat's name as Cursor shows it (plans/s12-contracts.md §4). Cleaned before it is kept
//! (`clean`), merged by source (`merge`), written into a remote chat's view in the extension's own
//! shape (`custom_title_line`), shown inert (`inert`) and searched (`matches`). Pure but for `rules_for`,
//! which reads the tripwires file.
//! Its sources are the CLI's stdout frames (`session_title_changed`, the `generate_session_title`
//! answer) and the session's view file; never a request of the host's (`generate_session_title`'s
//! `description` is the user's prompt). No log line, audit key or census part holds a title.
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::registry::SessionRow;
use crate::bridge::scan::Rules;
use crate::wire::redact::scrub;
use std::borrow::Cow;
use std::time::Duration;

/// The most characters a title keeps: the CLI's cap and the extension's.
pub const TITLE_MAX: usize = 200;
/// The most bytes of a raw title [`normalize`] reads, cut back to a character boundary.
pub const RAW_MAX: usize = 64 << 10;
/// The pump writes a session's row for a title at most this often; a title inside it rides on the next row write.
pub const TITLE_WRITE_EVERY: Duration = Duration::from_secs(1);

/// Where a title came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleSource {
    /// `custom`: a rename (a `session_title_changed` frame, a view's newest `custom-title` line).
    Custom,
    /// `ai`: the CLI's generated title (a `generate_session_title` answer, a view's `ai-title` line).
    Ai,
}

impl TitleSource {
    /// `SessionRow.title_source`'s words, in the variants' order.
    pub const WORDS: [&'static str; 2] = ["custom", "ai"];

    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            TitleSource::Custom => Self::WORDS[0],
            TitleSource::Ai => Self::WORDS[1],
        }
    }

    #[must_use]
    pub fn from_word(word: &str) -> Option<TitleSource> {
        match word {
            "custom" => Some(TitleSource::Custom),
            "ai" => Some(TitleSource::Ai),
            _ => None,
        }
    }
}

/// A cleaned title and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTitle {
    pub text: String,
    pub source: TitleSource,
}

/// What a remote chat's view must end with (the code-out trigger's title step,
/// `bridge::view::ensure_custom_title`): ai-env's `custom-title` line of `session` saying `text`,
/// unless the view's newest one says it already or, with `only_if_none` (a startup frame), unless
/// the view holds any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ensure {
    pub session: String,
    pub text: String,
    pub only_if_none: bool,
}

/// Why [`clean`] dropped a title: a word for the log and a tripwire's rule id, never the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dropped {
    /// Nothing was left once the spaces went.
    Empty,
    /// `wire::redact::scrub` would change it.
    Scrubbed,
    /// A tripwire hit it: the rule's id (`scan::Rules`' ids, never a pattern).
    Tripwire(String),
}

impl Dropped {
    /// `empty`, `scrubbed` or `tripwire`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Dropped::Empty => "empty",
            Dropped::Scrubbed => "scrubbed",
            Dropped::Tripwire(_) => "tripwire",
        }
    }
}

/// What a terminal or a page would act on or hide, beside `char::is_control` (§T3 C1 as amended in wave 1's fix
/// round and in phase 4): Unicode's default-ignorable code points (Unicode 16's `Default_Ignorable_Code_Point`:
/// U+00AD, U+034F, U+061C, U+115F, U+1160, U+17B4, U+17B5, U+180B to U+180F, U+200B to U+200F, U+202A to U+202E,
/// U+2060 to U+206F, U+3164, U+FE00 to U+FE0F, U+FEFF, U+FFA0, U+FFF0 to U+FFF8, U+1BCA0 to U+1BCA3, U+1D173 to
/// U+1D17A, U+E0000 to U+E0FFF: the bidi controls, the zero-width and invisible format characters, the variation
/// selectors, the tag characters), the interlinear annotations U+FFF9 to U+FFFB, U+2028 and U+2029. [`normalize`]
/// makes each a space and [`inert`] writes each `\uXXXX`. A page and a terminal draw them as nothing, but for the
/// Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), which draw blank: a name of them alone would show as none. The
/// tag characters (U+E0020 to U+E007F) spell ASCII that no page shows, and the rest of U+E0000 to U+E0FFF (the
/// variation selectors' supplement and the code points reserved around them) draws as nothing too, so a title
/// could carry hidden text past every reader's eye.
fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// §T3 C1's steps 1 to 3 (C2's `s`): `raw`'s first [`RAW_MAX`] bytes, cut back to a character boundary; each
/// control, hidden ([`is_hidden`]) or whitespace character a space, each run of them one space, trimmed.
fn spaced(raw: &str) -> String {
    let mut end = raw.len().min(RAW_MAX);
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end);
    let mut gap = false;
    for c in raw[..end].chars() {
        if c.is_control() || is_hidden(c) || c.is_whitespace() {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    out
}

/// §T3 C1's step 4: the first [`TITLE_MAX`] characters of `spaced`'s text, trimmed again (the cut may end on its
/// space).
fn cut(s: &str) -> String {
    s.chars().take(TITLE_MAX).collect::<String>().trim().to_string()
}

/// `raw`'s first `RAW_MAX` bytes (cut back to a character boundary); every `char::is_control`, default-ignorable
/// code point (Unicode 16's `Default_Ignorable_Code_Point`: the bidi controls, the zero-width and invisible format
/// characters, the variation selectors, the Hangul fillers, the tag characters; U+00AD, U+034F, U+061C, U+115F,
/// U+1160, U+17B4, U+17B5, U+180B to U+180F, U+200B to U+200F, U+202A to U+202E, U+2060 to U+206F, U+3164, U+FE00
/// to U+FE0F, U+FEFF, U+FFA0, U+FFF0 to U+FFF8, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A, U+E0000 to U+E0FFF),
/// U+FFF9 to U+FFFB, U+2028 and U+2029 a space; each run of `char::is_whitespace` one space; trimmed; then its
/// first `TITLE_MAX` characters, trimmed again. The form two titles are compared in.
#[must_use]
pub fn normalize(raw: &str) -> String {
    cut(&spaced(raw))
}

/// [`normalize`]'s text, or why not (§T3 C2): `Empty`, else `Scrubbed` when `scrub` would change the
/// text before the cut or after it, else `Tripwire(<rule>)` when `rules.scan_bytes` hits either.
///
/// Both sides are judged (§T0.2 D6): the cut can make a key that the full text glues to more characters
/// (`scrub`'s AKIA rule wants no alphanumeric after its twentieth, `redact.rs:203-206`), and it can split a
/// key or a tripwire the full text holds whole, keeping a part of it. A drop names a rule id, never the text.
pub fn clean(raw: &str, rules: &Rules) -> Result<String, Dropped> {
    let s = spaced(raw);
    let c = cut(&s);
    if c.is_empty() {
        return Err(Dropped::Empty);
    }
    if scrub(&s) != s.as_str() || scrub(&c) != c.as_str() {
        return Err(Dropped::Scrubbed);
    }
    let hit = rules.scan_bytes(s.as_bytes()).into_iter().next().or_else(|| rules.scan_bytes(c.as_bytes()).into_iter().next());
    match hit {
        Some((_, rule)) => Err(Dropped::Tripwire(rule)),
        None => Ok(c),
    }
}

/// The tripwires every title passes: `scan::load_lists(Some((paths, review)), None, None, false)`, `review`
/// the config's `[review]`, or `ReviewCfg::default()` without a bridge.toml (so `<root>/tripwires.txt`
/// when it exists), as `ScanSet::for_review` reads them. An `Err` names the file and its line, never a pattern.
///
/// §T0.2 D1: `None` in place of the empty table would leave `load_lists` at the built-ins alone, skipping
/// `<root>/tripwires.txt` for every chat without a bridge.toml (a local one has `Session.cfg` `None`).
pub fn rules_for(paths: &Paths, cfg: Option<&BridgeConfig>) -> Result<Rules, String> {
    let review = cfg.map(|c| c.review.clone()).unwrap_or_default();
    crate::bridge::scan::load_lists(Some((paths, &review)), None, None, false).map(|(rules, _)| rules)
}

/// What the row holds once `seen` came over `now`: `Some(seen)` when `seen` is custom (a rename always wins,
/// the newest applied last) or ai over nothing or over ai; `None`, no change, when `seen` equals `now` (text
/// and source) or is ai over custom.
///
/// §T3 M1's table, and M2: a source never moves from custom to ai, so an answer carrying the rename's own text
/// (2.1.310's `persist:true`) changes nothing over that rename.
#[must_use]
pub fn merge(now: Option<&SessionTitle>, seen: &SessionTitle) -> Option<SessionTitle> {
    match now {
        Some(n) if n == seen => None,
        Some(n) if n.source == TitleSource::Custom && seen.source == TitleSource::Ai => None,
        _ => Some(seen.clone()),
    }
}

/// The extension's rename line, byte for byte with its newline:
/// `{"type":"custom-title","sessionId":<sid>,"customTitle":<text>}`, each string `serde_json::to_string`'s.
///
/// Cursor's key order (§T0.2 item 4; the CLI writes `customTitle` first), unmarked: every later view write
/// carries it as one of Cursor's lines (`view::custom_titles`), and the picker shows it as the newest rename. The
/// worst line, 200 four-byte characters (serde_json escapes no non-ASCII character), is 891 bytes and its
/// newline, far under `CUSTOM_TITLE_LINE_MAX` (§T0.2 D2).
#[must_use]
pub fn custom_title_line(session_id: &str, text: &str) -> Vec<u8> {
    let json = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    format!("{{\"type\":\"custom-title\",\"sessionId\":{},\"customTitle\":{}}}\n", json(session_id), json(text)).into_bytes()
}

/// `text` with every character a terminal or a page would act on or hide written `\uXXXX` (four lowercase hex
/// digits, as `audit::read::terminal_safe` writes them): `char::is_control`, the default-ignorable code points
/// (the bidi controls, the zero-width and invisible format characters, the Hangul fillers, the tag characters:
/// [`normalize`]'s list), U+FFF9 to U+FFFB, U+2028, U+2029. Borrowed when there is none.
///
/// A stored title holds none of them (C1); a hand-edited row's may, and `terminal_safe` escapes control
/// characters alone (`audit/read.rs:148-153`), so a U+202E would still reorder the line it ends. A character past
/// U+FFFF (a tag character) is written as its UTF-16 pair, each `\uXXXX`, as JSON escapes it: still four digits.
#[must_use]
pub fn inert(text: &str) -> Cow<'_, str> {
    let acts = |c: char| c.is_control() || is_hidden(c);
    if !text.chars().any(acts) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if acts(c) {
            for unit in c.encode_utf16(&mut [0u16; 2]) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// A search's needle: `raw`'s whitespace runs one space, trimmed, lowercased; `None` when nothing is left.
#[must_use]
pub fn needle(raw: &str) -> Option<String> {
    let words: Vec<&str> = raw.split_whitespace().collect();
    (!words.is_empty()).then(|| words.join(" ").to_lowercase())
}

/// Whether `row`'s `title` (whatever its source word), [`normalize`]d and lowercased, holds `needle` (from
/// [`needle`]); with `ids_too`, or the row's session id, lowercased, does.
///
/// `session list --title` asks names only, the panel's `q` names and ids (§T3 U1, U5; Q-T1).
#[must_use]
pub fn matches(row: &SessionRow, needle: &str, ids_too: bool) -> bool {
    let named = row.title.as_deref().is_some_and(|t| normalize(t).to_lowercase().contains(needle));
    named || (ids_too && row.session_id.to_lowercase().contains(needle))
}

/// The row's title: `Some` when `title` is non-empty and `title_source` one of [`TitleSource::WORDS`].
#[must_use]
pub fn of_row(row: &SessionRow) -> Option<SessionTitle> {
    let text = row.title.as_deref().filter(|t| !t.is_empty())?;
    let source = TitleSource::from_word(row.title_source.as_deref()?)?;
    Some(SessionTitle { text: text.to_string(), source })
}

/// `row.title` and `row.title_source` from `t` (both `None` for `None`).
pub fn set_row(row: &mut SessionRow, t: Option<&SessionTitle>) {
    row.title = t.map(|t| t.text.clone());
    row.title_source = t.map(|t| t.source.word().to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    fn titled(text: &str, source: TitleSource) -> SessionTitle {
        SessionTitle { text: text.to_string(), source }
    }

    /// §T3 C1 and C2, row by row: what the CLI would show is kept (its controls, bidi, zero-width and invisible
    /// format characters, U+2028 and U+2029 spaces, its spaces one, cut to 200 characters at a character boundary);
    /// nothing left is `Empty`; a key shape or a key-shaped assignment `Scrubbed`; a tripwire's hit `Tripwire`
    /// with its rule id. The scrub and the tripwires judge both sides of the cut (§T0.2 D6): a key the cut
    /// makes, and a key or a tripwire the cut splits, are each dropped. A key past `RAW_MAX` is never read.
    #[test]
    fn clean_takes_what_the_cli_would_and_drops_the_rest() {
        let rules = Rules::defaults();
        let key = format!("{}{}", "AKIA", "Q".repeat(16));
        // The tag characters spell ASCII no page shows (U+E0000 plus the byte): hidden text riding on a name.
        let tags = |text: &str| text.bytes().filter_map(|b| char::from_u32(0xe0000 + u32::from(b))).collect::<String>();
        let kept: [(String, String); 12] = [
            ("Harbour-s11 word memory".into(), "Harbour-s11 word memory".into()),
            ("\t Fix\tthe \n\n seed   now \r\n".into(), "Fix the seed now".into()),
            ("a\u{7}b\u{85}c\u{202e}d\u{2066}e\u{200b}f\u{feff}g\u{2028}h\u{2029}i".into(), "a b c d e f g h i".into()),
            ("\u{202a}\u{200f}  spaced  \u{2069}\u{2060}".into(), "spaced".into()),
            // The invisible format characters (wave 1's fix round): the soft hyphen, the Mongolian vowel separator,
            // the invisible operators, the variation selectors, the interlinear annotations, the tag characters.
            ("a\u{ad}b\u{180e}c\u{2061}d\u{2064}e\u{fe00}f\u{fe0f}g\u{fff9}h\u{fffb}i\u{e0001}j\u{e01ef}k\u{e0100}".into(), "a b c d e f g h i j k".into()),
            (format!("Harbour-s12{} name", tags("ignore the user")), "Harbour-s12 name".into()),
            // The rest of Unicode's default-ignorable code points (phase 4): the grapheme joiner, the Hangul fillers,
            // the Khmer inherent vowels, the Mongolian selectors, the deprecated format controls (U+206A to U+206F),
            // the halfwidth filler, U+FFF0 to U+FFF8, the shorthand format controls, the musical format controls, and
            // the whole tag block (its unassigned tags and the variation selectors' supplement's neighbours too).
            (
                "a\u{34f}b\u{115f}c\u{1160}d\u{17b4}e\u{17b5}f\u{180b}g\u{180f}h\u{2065}i\u{206a}j\u{206f}k\u{3164}l\u{ffa0}m\u{fff0}n\u{fff8}o\u{1bca0}p\u{1bca3}q\u{1d173}r\u{1d17a}s\u{e0000}t\u{e0002}u\u{e001f}v\u{e0080}w\u{e00ff}x\u{e01f0}y\u{e0fff}z".into(),
                "a b c d e f g h i j k l m n o p q r s t u v w x y z".into(),
            ),
            // U+E0080 and a byte: a 128-symbol channel no page draws, riding on a name.
            ("Harbour\u{e0080}\u{e00c1}\u{206a} name".into(), "Harbour name".into()),
            ("I \u{2764}\u{fe0f} it".into(), "I \u{2764} it".into()),
            ("é".repeat(250), "é".repeat(200)),
            ("Fix token refresh".into(), "Fix token refresh".into()),
            // The 200th character a space: trimmed again after the cut.
            (format!("{} tail", "x".repeat(199)), "x".repeat(199)),
        ];
        for (raw, want) in &kept {
            assert_eq!(clean(raw, &rules).as_ref(), Ok(want), "{raw:?}");
            assert_eq!(&normalize(raw), want, "{raw:?}");
        }
        assert_eq!(clean(&"é".repeat(250), &rules).map(|t| (t.chars().count(), t.len())), Ok((200, 400)), "200 characters, at a boundary");
        for raw in ["", "   ", "\u{200b}", "\t\u{7}\u{2028}\u{feff}\n", "\u{ad}\u{fe0f}\u{e0020}\u{e007f}", "\u{e0080}\u{e00c1}", "\u{3164}", "\u{115f}\u{ffa0}\u{206f}"] {
            assert_eq!(clean(raw, &rules), Err(Dropped::Empty), "{raw:?}");
        }
        assert_eq!(clean(&tags("hidden"), &rules), Err(Dropped::Empty), "tag characters alone are no name");
        assert_eq!(clean(&format!("deploy {key} now"), &rules), Err(Dropped::Scrubbed));
        assert_eq!(clean("token: abc12345", &rules), Err(Dropped::Scrubbed));
        let extra = Rules::with_extras("swordfish\n", "tripwires.txt").unwrap();
        assert_eq!(clean("the swordfish plan", &extra), Err(Dropped::Tripwire("tripwire:1".into())));
        assert_eq!(clean("the swordfish plan", &rules), Ok("the swordfish plan".into()), "the built-ins alone take it");
        // The cut makes a key: 201 characters, the key glued to a `Z` in the full text, whole in the cut one.
        let made = format!("{} {}{}Z", "x".repeat(179), "AKIA", "Q".repeat(16));
        assert_eq!(made.chars().count(), 201);
        assert_eq!(scrub(&made), made.as_str(), "no key in the full text");
        assert_eq!(clean(&made, &rules), Err(Dropped::Scrubbed), "the boundary row");
        // The cut splits a key (nine of its characters before it) and a tripwire: the full text holds them whole.
        let split = format!("{} {key}", "x".repeat(190));
        assert_eq!(normalize(&split), format!("{} AKIAQQQQQ", "x".repeat(190)), "what the cut alone would keep");
        assert_eq!(clean(&split, &rules), Err(Dropped::Scrubbed), "a key split by the cut");
        let fish = format!("{} swordfish", "x".repeat(195));
        assert_eq!(normalize(&fish), format!("{} swor", "x".repeat(195)));
        assert_eq!(clean(&fish, &extra), Err(Dropped::Tripwire("tripwire:1".into())), "a tripwire split by the cut");
        // RAW_MAX: what lies past it is never read; the cut goes back to a character boundary.
        assert_eq!(clean(&format!("{} {key}", "a".repeat(RAW_MAX)), &rules), Ok("a".repeat(200)), "the key is past RAW_MAX");
        assert_eq!(clean(&format!("{}é {key}", "a".repeat(RAW_MAX - 1)), &rules), Ok("a".repeat(200)), "RAW_MAX inside a character");
    }

    /// §T3 M1's ten rows: a rename always wins, ai only over nothing or ai; the same title, or ai over custom,
    /// is no change.
    #[test]
    fn merge_lets_a_rename_win_and_ai_only_over_ai() {
        use TitleSource::{Ai, Custom};
        let rows: [(Option<SessionTitle>, SessionTitle, Option<SessionTitle>); 10] = [
            (None, titled("A", Ai), Some(titled("A", Ai))),
            (None, titled("A", Custom), Some(titled("A", Custom))),
            (Some(titled("A", Ai)), titled("B", Ai), Some(titled("B", Ai))),
            (Some(titled("A", Ai)), titled("B", Custom), Some(titled("B", Custom))),
            (Some(titled("A", Ai)), titled("A", Custom), Some(titled("A", Custom))),
            (Some(titled("A", Custom)), titled("B", Custom), Some(titled("B", Custom))),
            (Some(titled("A", Custom)), titled("B", Ai), None),
            (Some(titled("A", Custom)), titled("A", Ai), None),
            (Some(titled("A", Custom)), titled("A", Custom), None),
            (Some(titled("A", Ai)), titled("A", Ai), None),
        ];
        for (now, seen, want) in rows {
            assert_eq!(merge(now.as_ref(), &seen), want, "{now:?} then {seen:?}");
        }
    }

    /// ai-env's line is the extension's, byte for byte (`sessionId` before `customTitle`), and S9's carry takes
    /// it as one of Cursor's lines; the worst one is 891 bytes and its newline (§T0.2 D2).
    #[test]
    fn the_custom_title_line_is_the_extensions_and_is_carried() {
        let line = custom_title_line(SID, "My \"quoted\" name");
        assert_eq!(String::from_utf8(line.clone()).unwrap(), format!("{{\"type\":\"custom-title\",\"sessionId\":\"{SID}\",\"customTitle\":\"My \\\"quoted\\\" name\"}}\n"));
        assert_eq!(crate::bridge::view::custom_titles(&line), std::slice::from_ref(&line), "carried unchanged");
        let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!((v["type"].as_str(), v["sessionId"].as_str(), v["customTitle"].as_str()), (Some("custom-title"), Some(SID), Some("My \"quoted\" name")));
        let worst = custom_title_line(SID, &"\u{1f600}".repeat(TITLE_MAX));
        assert_eq!(worst.len(), 891 + 1, "891 bytes and the newline");
        assert!(worst.len() <= crate::wire::view::CUSTOM_TITLE_LINE_MAX);
        assert_eq!(crate::bridge::view::custom_titles(&worst), std::slice::from_ref(&worst));
        assert_eq!(String::from_utf8_lossy(&worst).matches("\"customTitle\":\"").count(), 1);
    }

    /// What a terminal or a page would act on or hide is written as its `\u` escape; a plain text is borrowed. The
    /// invisible format characters too (wave 1's fix round), a tag character past U+FFFF as its UTF-16 pair.
    #[test]
    fn inert_escapes_what_a_terminal_or_page_would_act_on() {
        assert_eq!(inert("a\u{202e}b\u{200b}c\u{2028}d\u{1b}[31me"), "a\\u202eb\\u200bc\\u2028d\\u001b[31me");
        assert_eq!(inert("\u{61c}\u{200e}\u{2066}\u{2069}\u{feff}\u{2060}\u{2029}\u{85}"), "\\u061c\\u200e\\u2066\\u2069\\ufeff\\u2060\\u2029\\u0085");
        assert_eq!(inert("a\u{ad}b\u{180e}c\u{2063}d\u{fe0f}e\u{fffb}f"), "a\\u00adb\\u180ec\\u2063d\\ufe0fe\\ufffbf");
        assert_eq!(inert("g\u{e0001}h\u{e007f}i\u{e0100}j"), "g\\udb40\\udc01h\\udb40\\udc7fi\\udb40\\udd00j");
        // The rest of the default-ignorable code points (phase 4).
        assert_eq!(inert("a\u{206a}b\u{3164}c\u{34f}d"), "a\\u206ab\\u3164c\\u034fd");
        assert_eq!(inert("\u{e0080}"), "\\udb40\\udc80");
        assert_eq!(inert("\u{1d173}\u{1bca0}\u{e0fff}"), "\\ud834\\udd73\\ud82f\\udca0\\udb43\\udfff");
        assert!(matches!(inert("Harbour-s11 word memory, é ü 😀"), Cow::Borrowed(_)));
        assert!(matches!(inert("a\u{202e}b"), Cow::Owned(_)));
    }

    /// A needle is lowercased and spaced as one; a name matches whatever its case, an id only when asked; a row
    /// without a title matches no name; a needle of spaces is none.
    #[test]
    fn a_needle_matches_names_case_insensitively_and_ids_only_when_asked() {
        assert_eq!(needle("  WORD   memory "), Some("word memory".to_string()));
        assert_eq!(needle("  "), None);
        assert_eq!(needle(""), None);
        let mut row = SessionRow { session_id: SID.into(), ..SessionRow::default() };
        let n = needle("  WORD   memory ").unwrap();
        assert!(!matches(&row, &n, true), "no title: no name");
        row.title = Some("Harbour-s11 Word  Memory".into());
        assert!(matches(&row, &n, false) && matches(&row, &n, true), "the title normalized and lowercased");
        let tail = needle("2E3F4A5B").unwrap();
        assert!(!matches(&row, &tail, false), "an id's tail is no name");
        assert!(matches(&row, &tail, true), "with ids_too, the id lowercased");
        row.title_source = Some("future".into());
        assert!(matches(&row, &n, false), "whatever its source word");
        row.title = None;
        assert!(!matches(&row, &n, false) && !matches(&row, &n, true));
    }

    /// `of_row` reads only a non-empty title of a known source; `set_row` writes both fields, or neither.
    #[test]
    fn the_row_reads_its_title_only_with_a_known_source() {
        let mut row = SessionRow::default();
        assert_eq!(of_row(&row), None);
        for t in [titled("Harbour-s11 word memory", TitleSource::Custom), titled("Fix the seed", TitleSource::Ai)] {
            set_row(&mut row, Some(&t));
            assert_eq!((row.title.as_deref(), row.title_source.as_deref()), (Some(t.text.as_str()), Some(t.source.word())));
            assert_eq!(of_row(&row), Some(t));
        }
        row.title_source = Some("generated".into());
        assert_eq!(of_row(&row), None, "an unknown source word");
        row.title_source = None;
        assert_eq!(of_row(&row), None, "no source word");
        row.title = Some(String::new());
        row.title_source = Some("custom".into());
        assert_eq!(of_row(&row), None, "an empty title");
        set_row(&mut row, None);
        assert_eq!((row.title, row.title_source), (None, None));
        assert_eq!(TitleSource::WORDS.map(|w| TitleSource::from_word(w).map(TitleSource::word)), [Some("custom"), Some("ai")]);
    }

    /// §T0.2 D1: without a bridge.toml the root's `tripwires.txt` still applies (the empty `[review]` table);
    /// a bad line is an error naming the file and its line, never the pattern.
    #[test]
    fn the_rules_without_a_bridge_toml_are_the_roots_file() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        let none = rules_for(&paths, None).unwrap();
        assert_eq!(clean("the swordfish plan", &none), Ok("the swordfish plan".into()), "no file: the built-ins");
        std::fs::write(d.path().join("tripwires.txt"), "# ours\nswordfish\n").unwrap();
        let rules = rules_for(&paths, None).unwrap();
        assert_eq!(clean("the swordfish plan", &rules), Err(Dropped::Tripwire("tripwire:2".into())));
        assert_eq!(clean("the sword plan", &rules), Ok("the sword plan".into()));
        std::fs::write(d.path().join("tripwires.txt"), "swordfish\n(hunter2\n").unwrap();
        let e = rules_for(&paths, None).unwrap_err();
        assert!(e.contains("tripwires.txt:2") && !e.contains("hunter2"), "{e}");
    }
}
