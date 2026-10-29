//! Cursors (plans/s13-contracts.md §P-proto-sdk.6.7, P-R60 to P-R63).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::SourceError;

/// The prefix of a version-1 cursor's text.
const PREFIX: &str = "c1.";
/// The one refusal of a text that is not one of this source's cursors (P-R61): no oracle.
const REFUSAL: &str = "cursor: not one of this source's cursors";

/// What a cursor's base64 holds, in this key order: `{"o":<op>,"s":<source>,"v":<state>}` (P-R60).
#[derive(Serialize)]
struct Sealed<'a, T> {
    o: &'a str,
    s: &'a str,
    v: &'a T,
}

/// A cursor's JSON read back: exactly the three keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Opened {
    o: String,
    s: String,
    v: serde_json::Value,
}

fn refusal() -> SourceError {
    SourceError::InvalidArgument(REFUSAL.to_string())
}

/// P-R61: the JSON object inside `text`, or the one refusal.
fn open(text: &str) -> Result<Opened, SourceError> {
    if text.len() > Cursor::MAX_LEN {
        return Err(refusal());
    }
    let body = text.strip_prefix(PREFIX).ok_or_else(refusal)?;
    let json = URL_SAFE_NO_PAD.decode(body).map_err(|_| refusal())?;
    serde_json::from_slice(&json).map_err(|_| refusal())
}

/// An opaque continuation, bound to one source and op (P-R60 to P-R63). Serialized as a JSON string.
/// Pagination state, not a capability: anyone can read it, and a source checks every decoded value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cursor(String);

impl Cursor {
    /// The longest cursor text.
    pub const MAX_LEN: usize = 4096;

    /// `c1.` then the URL-safe unpadded base64 of `{"o":<op>,"s":<source>,"v":<state>}` (P-R60); past
    /// `MAX_LEN` it is `Internal("cursor: <n> bytes, above 4096")`.
    pub fn encode<T: Serialize>(source: &str, op: &str, state: &T) -> Result<Cursor, SourceError> {
        let json = serde_json::to_vec(&Sealed { o: op, s: source, v: state }).map_err(|e| SourceError::Internal(format!("cursor: {e}")))?;
        let text = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json));
        if text.len() > Cursor::MAX_LEN {
            return Err(SourceError::Internal(format!("cursor: {} bytes, above {}", text.len(), Cursor::MAX_LEN)));
        }
        Ok(Cursor(text))
    }

    /// The state back, for this source and op only (P-R61): another source's or op's cursor, or a state
    /// that is not a `T`, is the one refusal.
    pub fn decode<T: DeserializeOwned>(&self, source: &str, op: &str) -> Result<T, SourceError> {
        let opened = open(&self.0)?;
        if opened.s != source || opened.o != op {
            return Err(refusal());
        }
        serde_json::from_value(opened.v).map_err(|_| refusal())
    }

    /// A cursor of that text, or `InvalidArgument("cursor: not one of this source's cursors")` for anything
    /// that is not a cursor's form (P-R61).
    pub fn parse(text: &str) -> Result<Cursor, SourceError> {
        open(text)?;
        Ok(Cursor(text.to_string()))
    }

    /// The cursor's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Cursor {
    type Error = SourceError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Cursor::parse(&text)
    }
}

impl From<Cursor> for String {
    fn from(cursor: Cursor) -> String {
        cursor.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct State {
        offset: u64,
        after: String,
    }

    fn refused() -> SourceError {
        SourceError::InvalidArgument("cursor: not one of this source's cursors".into())
    }

    /// P-T20.
    #[test]
    fn cursor_round_trips_and_refuses_another_ops_or_a_forged_one() {
        let state = State { offset: 40, after: "row-39".into() };
        let cursor = Cursor::encode("echo", "lines", &state).expect("encodes");
        assert!(cursor.as_str().starts_with("c1."), "{}", cursor.as_str());
        assert_eq!(cursor.decode::<State>("echo", "lines"), Ok(state));
        let json = serde_json::to_string(&cursor).expect("serializes");
        assert_eq!(json, format!("\"{}\"", cursor.as_str()));
        assert_eq!(serde_json::from_str::<Cursor>(&json).expect("deserializes"), cursor);
        assert_eq!(Cursor::parse(cursor.as_str()), Ok(cursor.clone()));
        assert_eq!(String::from(cursor.clone()), cursor.as_str());
        let opened = URL_SAFE_NO_PAD.decode(&cursor.as_str()[3..]).expect("base64");
        assert_eq!(opened, br#"{"o":"lines","s":"echo","v":{"offset":40,"after":"row-39"}}"#);

        assert_eq!(cursor.decode::<State>("echo-2", "lines"), Err(refused()));
        assert_eq!(cursor.decode::<State>("echo", "echo"), Err(refused()));
        assert_eq!(cursor.decode::<u64>("echo", "lines"), Err(refused()));
        let rest = &cursor.as_str()[3..];
        let forged = [
            format!("c2.{rest}"),
            "c1.!!not base64!!".to_string(),
            format!("c1.{}", "A".repeat(4094)),
            format!("c1.{}", URL_SAFE_NO_PAD.encode("not JSON")),
            format!("c1.{}", URL_SAFE_NO_PAD.encode(r#"{"o":"lines","s":"echo"}"#)),
            format!("c1.{}", URL_SAFE_NO_PAD.encode(r#"{"o":"lines","s":"echo","v":1,"w":2}"#)),
            format!("c1.{}", URL_SAFE_NO_PAD.encode("[1,2]")),
        ];
        assert_eq!(forged[2].len(), 4097);
        for text in &forged {
            assert_eq!(Cursor::parse(text), Err(refused()), "{text}");
        }
        assert!(serde_json::from_str::<Cursor>(&format!("\"c2.{rest}\"")).is_err());

        // The first state too long makes a 4097-byte text: unpadded base64 is never 4n + 1 long, so 4096 is
        // skipped from 4095.
        let first = (0..4096).map(|pad| Cursor::encode("echo", "lines", &"x".repeat(pad))).find(Result::is_err);
        assert_eq!(first, Some(Err(SourceError::Internal("cursor: 4097 bytes, above 4096".into()))));
    }
}
