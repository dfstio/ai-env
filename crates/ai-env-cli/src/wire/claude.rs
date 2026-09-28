//! Recognisers for the Claude stream-json frames the wrapper must act on, and
//! builders for the few frames it writes itself. Pure and serde-only: the S2
//! pump (`bridge::pump`, `bridge::hoststate`) and later the VM path use them.
//!
//! Only a line whose first byte is `{`, that parses as a JSON object and has a
//! string `type` is classified; everything else is [`ChildFrame::Other`] /
//! [`HostFrame::Other`] and is forwarded verbatim by the pump. Fields are
//! peeked as raw JSON and read leniently: a field of an unexpected type reads
//! as absent instead of turning the whole frame into `Other`, so the pump's
//! bookkeeping (pending requests, outstanding user lines) never silently loses
//! a frame it should have seen. Strings are borrowed from the line unless they
//! contain escapes.
//!
//! Frame shapes (Claude Code 2.1.278/2.1.282, stream-json both ways):
//! * child → host `{"type":"transcript_mirror","filePath":…,"entries":[…]}`
//!   (only with `--session-mirror`; entries are the transcript objects, kept
//!   as raw slices so they are appended byte-for-byte);
//! * `{"type":"system","subtype":"init","session_id":…,"cwd":…,…}`;
//! * `{"type":"control_request","request_id":…,"request":{"subtype":…,…}}`
//!   in both directions, answered by
//!   `{"type":"control_response","response":{"subtype":"success"|"error","request_id":…,…}}`;
//! * host → child `{"type":"control_cancel_request","request_id":…}` (no reply);
//! * `{"type":"user","uuid":…,…}` (host → child), echoed back with
//!   `"isReplay":true` under `--replay-user-messages`;
//! * `{"type":"result","subtype":…,"is_error":…,"errors":[…],"user_message_uuid":…,"user_message_uuids":[…],…}`.
use bytes::Bytes;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::borrow::Cow;

/// Host → CLI control requests whose effect is session state a respawned
/// child must be given again (after `initialize`). `set_*` and
/// `mcp_set_servers` keep the last value per subtype; `apply_flag_settings`
/// shallow-merges into the CLI's session flag layer (a `null` deletes a key),
/// so every one is replayed in order. 2.1.278+ sends mid-session model and
/// `viewMode` changes as `apply_flag_settings`, never `set_model`; `set_model`,
/// `set_cwd` and `set_mcp_permission_mode_override` stay for forward
/// compatibility (the SDK exposes them; the last is on the CLI's own list of
/// session-state requests). Not state (forwarded, never replayed):
/// `update_settings`, `mcp_toggle`, `reload_*` (file-backed, re-read by any
/// child) and one-shot actions (`interrupt`, `rewind_files`, `rename_session`,
/// `mcp_message`, `stop_task`, …); `remote_control` is session-scoped and is
/// lost on a respawn (documented residual).
pub const STATE_SUBTYPES: [&str; 7] = [
    "set_permission_mode",
    "set_model",
    "set_max_thinking_tokens",
    "mcp_set_servers",
    "set_cwd",
    "set_mcp_permission_mode_override",
    "apply_flag_settings",
];

/// The subtype whose every occurrence is replayed (the others keep only their last value).
pub const CUMULATIVE_SUBTYPE: &str = "apply_flag_settings";

/// The CLI's resume-miss text; in stream-json mode it is printed on stderr
/// AND carried as `errors[0]` of an `error_during_execution` result on stdout.
pub const RESUME_MISS_MARKER: &str = "No conversation found with session ID:";

/// What the pump needs to know about one child → host line.
#[derive(Debug, Clone)]
pub enum ChildFrame<'a> {
    /// `transcript_mirror`: never forwarded. A malformed frame has
    /// `file_path: None` or no entries and is counted as a reject.
    Mirror { file_path: Option<Cow<'a, str>>, entries: Vec<&'a RawValue> },
    /// `system`/`init`.
    Init { session_id: Option<Cow<'a, str>>, cwd: Option<Cow<'a, str>> },
    /// An answer to a request (the id is `response.request_id`).
    ControlResponse { request_id: Option<Cow<'a, str>>, subtype: Option<Cow<'a, str>> },
    /// A request from the CLI to the host (`can_use_tool`, `hook_callback`,
    /// `mcp_message`, `oauth_token_refresh`, …).
    ControlRequest { request_id: Option<Cow<'a, str>>, subtype: Option<Cow<'a, str>> },
    /// A user frame (with `--replay-user-messages`, the echo of a host line).
    User { uuid: Option<Cow<'a, str>>, is_replay: bool },
    /// The end of a turn (or a startup failure such as a resume miss).
    Result {
        subtype: Option<Cow<'a, str>>,
        is_error: bool,
        first_error: Option<Cow<'a, str>>,
        user_message_uuid: Option<Cow<'a, str>>,
        user_message_uuids: Vec<Cow<'a, str>>,
    },
    /// Everything else (`assistant`, `stream_event`, `keep_alive`, other
    /// `system` subtypes, non-JSON noise): forwarded untouched.
    Other,
}

/// What the pump needs to know about one host → child line.
#[derive(Debug, Clone)]
pub enum HostFrame<'a> {
    /// A request to the CLI; `request` is the raw `request` object (recorded
    /// byte-for-byte for a replay).
    ControlRequest { request_id: Option<Cow<'a, str>>, subtype: Option<Cow<'a, str>>, request: Option<&'a RawValue> },
    /// `control_cancel_request`: the host withdraws one of its requests.
    ControlCancel { request_id: Option<Cow<'a, str>> },
    /// The host answering a request of the CLI.
    ControlResponse { request_id: Option<Cow<'a, str>> },
    /// A user message (the uuid is minted by the extension's webview; absent
    /// on some synthetic sends).
    User { uuid: Option<Cow<'a, str>> },
    /// Everything else (`keep_alive`, non-JSON): forwarded untouched.
    Other,
}

/// `RawValue` has no `PartialEq`: compare raw slices by their text.
fn same_raw(a: &[&RawValue], b: &[&RawValue]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.get() == y.get())
}

impl PartialEq for ChildFrame<'_> {
    fn eq(&self, other: &Self) -> bool {
        use ChildFrame as F;
        match (self, other) {
            (F::Mirror { file_path: a, entries: x }, F::Mirror { file_path: b, entries: y }) => a == b && same_raw(x, y),
            (F::Init { session_id: a, cwd: x }, F::Init { session_id: b, cwd: y }) => a == b && x == y,
            (F::ControlResponse { request_id: a, subtype: x }, F::ControlResponse { request_id: b, subtype: y })
            | (F::ControlRequest { request_id: a, subtype: x }, F::ControlRequest { request_id: b, subtype: y }) => a == b && x == y,
            (F::User { uuid: a, is_replay: x }, F::User { uuid: b, is_replay: y }) => a == b && x == y,
            (
                F::Result { subtype: s1, is_error: e1, first_error: f1, user_message_uuid: u1, user_message_uuids: v1 },
                F::Result { subtype: s2, is_error: e2, first_error: f2, user_message_uuid: u2, user_message_uuids: v2 },
            ) => s1 == s2 && e1 == e2 && f1 == f2 && u1 == u2 && v1 == v2,
            (F::Other, F::Other) => true,
            _ => false,
        }
    }
}

impl PartialEq for HostFrame<'_> {
    fn eq(&self, other: &Self) -> bool {
        use HostFrame as H;
        match (self, other) {
            (H::ControlRequest { request_id: a, subtype: x, request: r1 }, H::ControlRequest { request_id: b, subtype: y, request: r2 }) => {
                a == b && x == y && r1.map(RawValue::get) == r2.map(RawValue::get)
            }
            (H::ControlCancel { request_id: a }, H::ControlCancel { request_id: b }) | (H::ControlResponse { request_id: a }, H::ControlResponse { request_id: b }) => a == b,
            (H::User { uuid: a }, H::User { uuid: b }) => a == b,
            (H::Other, H::Other) => true,
            _ => false,
        }
    }
}

/// Every field the recognisers look at, peeked as raw JSON.
#[derive(Deserialize)]
struct Peek<'a> {
    #[serde(rename = "type", borrow, default)]
    ty: Option<&'a RawValue>,
    #[serde(borrow, default)]
    subtype: Option<&'a RawValue>,
    #[serde(borrow, default)]
    request_id: Option<&'a RawValue>,
    #[serde(borrow, default)]
    request: Option<&'a RawValue>,
    #[serde(borrow, default)]
    response: Option<&'a RawValue>,
    #[serde(rename = "filePath", borrow, default)]
    file_path: Option<&'a RawValue>,
    #[serde(borrow, default)]
    entries: Option<&'a RawValue>,
    #[serde(borrow, default)]
    session_id: Option<&'a RawValue>,
    #[serde(borrow, default)]
    cwd: Option<&'a RawValue>,
    #[serde(borrow, default)]
    uuid: Option<&'a RawValue>,
    #[serde(rename = "isReplay", borrow, default)]
    is_replay: Option<&'a RawValue>,
    #[serde(borrow, default)]
    is_error: Option<&'a RawValue>,
    #[serde(borrow, default)]
    errors: Option<&'a RawValue>,
    #[serde(borrow, default)]
    user_message_uuid: Option<&'a RawValue>,
    #[serde(borrow, default)]
    user_message_uuids: Option<&'a RawValue>,
}

/// The two fields of a nested `request` / `response` object.
#[derive(Deserialize)]
struct Inner<'a> {
    #[serde(borrow, default)]
    subtype: Option<&'a RawValue>,
    #[serde(borrow, default)]
    request_id: Option<&'a RawValue>,
}

/// A string that borrows from the input when it has no escapes.
#[derive(Deserialize)]
struct Text<'a>(#[serde(borrow)] Cow<'a, str>);

fn peek(line: &[u8]) -> Option<Peek<'_>> {
    if line.first() != Some(&b'{') {
        return None;
    }
    serde_json::from_slice(line).ok()
}

fn text(raw: Option<&RawValue>) -> Option<Cow<'_, str>> {
    serde_json::from_str::<Text<'_>>(raw?.get()).ok().map(|t| t.0)
}

fn flag(raw: Option<&RawValue>) -> bool {
    raw.and_then(|r| serde_json::from_str::<bool>(r.get()).ok()).unwrap_or(false)
}

fn raw_items(raw: Option<&RawValue>) -> Vec<&RawValue> {
    raw.and_then(|r| serde_json::from_str::<Vec<&RawValue>>(r.get()).ok()).unwrap_or_default()
}

fn texts(raw: Option<&RawValue>) -> Vec<Cow<'_, str>> {
    raw_items(raw).into_iter().filter_map(|r| text(Some(r))).collect()
}

fn inner(raw: Option<&RawValue>) -> Option<Inner<'_>> {
    serde_json::from_str::<Inner<'_>>(raw?.get()).ok()
}

/// Classify one child → host line (without its `\n`).
#[must_use]
pub fn classify_child(line: &[u8]) -> ChildFrame<'_> {
    let Some(p) = peek(line) else {
        return ChildFrame::Other;
    };
    let Some(ty) = text(p.ty) else {
        return ChildFrame::Other;
    };
    match ty.as_ref() {
        "transcript_mirror" => ChildFrame::Mirror { file_path: text(p.file_path), entries: raw_items(p.entries) },
        "system" if text(p.subtype).as_deref() == Some("init") => ChildFrame::Init { session_id: text(p.session_id), cwd: text(p.cwd) },
        "control_response" => {
            let r = inner(p.response);
            ChildFrame::ControlResponse {
                request_id: r.as_ref().and_then(|r| text(r.request_id)),
                subtype: r.as_ref().and_then(|r| text(r.subtype)),
            }
        }
        "control_request" => ChildFrame::ControlRequest {
            request_id: text(p.request_id),
            subtype: inner(p.request).and_then(|r| text(r.subtype)),
        },
        "user" => ChildFrame::User { uuid: text(p.uuid), is_replay: flag(p.is_replay) },
        "result" => ChildFrame::Result {
            subtype: text(p.subtype),
            is_error: flag(p.is_error),
            first_error: raw_items(p.errors).first().and_then(|e| text(Some(e))),
            user_message_uuid: text(p.user_message_uuid),
            user_message_uuids: texts(p.user_message_uuids),
        },
        _ => ChildFrame::Other,
    }
}

/// Classify one host → child line (without its `\n`).
#[must_use]
pub fn classify_host(line: &[u8]) -> HostFrame<'_> {
    let Some(p) = peek(line) else {
        return HostFrame::Other;
    };
    let Some(ty) = text(p.ty) else {
        return HostFrame::Other;
    };
    match ty.as_ref() {
        "control_request" => HostFrame::ControlRequest {
            request_id: text(p.request_id),
            subtype: inner(p.request).and_then(|r| text(r.subtype)),
            request: p.request,
        },
        "control_cancel_request" => HostFrame::ControlCancel { request_id: text(p.request_id) },
        "control_response" => HostFrame::ControlResponse { request_id: inner(p.response).and_then(|r| text(r.request_id)) },
        "user" => HostFrame::User { uuid: text(p.uuid) },
        _ => HostFrame::Other,
    }
}

/// Is `subtype` recorded as session state (see [`STATE_SUBTYPES`])?
#[must_use]
pub fn is_state_subtype(subtype: &str) -> bool {
    STATE_SUBTYPES.contains(&subtype)
}

/// The CLI's resume-miss result: an error `result` whose first error starts
/// with [`RESUME_MISS_MARKER`]. The sibling print-path failures
/// (`No message found with message.uuid of: …`, the drop-guard refusal)
/// share the frame shape, so the text decides, never the shape.
#[must_use]
pub fn is_resume_miss(frame: &ChildFrame<'_>) -> bool {
    matches!(frame, ChildFrame::Result { is_error: true, first_error: Some(e), .. } if e.starts_with(RESUME_MISS_MARKER))
}

/// A JSON string literal for `s` (quotes and escapes included).
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// `{"type":"control_request","request_id":<id>,"request":<raw>}` — a
/// recorded request re-sent under a fresh id; `request` is copied verbatim.
#[must_use]
pub fn control_request_line(request_id: &str, request: &RawValue) -> Bytes {
    Bytes::from(format!("{{\"type\":\"control_request\",\"request_id\":{},\"request\":{}}}", json_str(request_id), request.get()))
}

/// `{"type":"control_response","response":{"subtype":"success","request_id":<id>,"response":<raw>}}`.
#[must_use]
pub fn control_success_line(request_id: &str, response: &RawValue) -> Bytes {
    Bytes::from(format!(
        "{{\"type\":\"control_response\",\"response\":{{\"subtype\":\"success\",\"request_id\":{},\"response\":{}}}}}",
        json_str(request_id),
        response.get()
    ))
}

/// `{"type":"control_response","response":{"subtype":"error","request_id":<id>,"error":<message>}}`.
#[must_use]
pub fn control_error_line(request_id: &str, message: &str) -> Bytes {
    Bytes::from(format!(
        "{{\"type\":\"control_response\",\"response\":{{\"subtype\":\"error\",\"request_id\":{},\"error\":{}}}}}",
        json_str(request_id),
        json_str(message)
    ))
}

/// A child `control_response` line with `response.request_id` changed from
/// `from` to `to`, everything else byte-for-byte: the one quoted occurrence
/// of `from` is replaced (the pump's replay ids are fresh uuid v7s, unique in
/// the line). `None` when `from` does not occur exactly once — the caller
/// then forwards the line unchanged.
#[must_use]
pub fn rewrite_response_id(line: &[u8], from: &str, to: &str) -> Option<Bytes> {
    let needle = json_str(from);
    let hay = std::str::from_utf8(line).ok()?;
    if hay.matches(needle.as_str()).count() != 1 {
        return None;
    }
    let out = hay.replacen(needle.as_str(), &json_str(to), 1);
    // The result must still be a control_response answering `to`.
    match classify_child(out.as_bytes()) {
        ChildFrame::ControlResponse { request_id: Some(id), .. } if id == to => Some(Bytes::from(out)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(s: &str) -> Box<RawValue> {
        RawValue::from_string(s.to_string()).unwrap()
    }

    #[test]
    fn non_json_and_typeless_lines_are_other() {
        for line in [&b""[..], b"hello", b" {\"type\":\"user\"}", b"{", b"{\"a\":1}", b"{\"type\":7}", b"[1,2]", b"{\"type\":\"user\"} trailing"] {
            assert_eq!(classify_child(line), ChildFrame::Other, "{:?}", String::from_utf8_lossy(line));
            assert_eq!(classify_host(line), HostFrame::Other, "{:?}", String::from_utf8_lossy(line));
        }
        assert_eq!(classify_child(br#"{"type":"keep_alive"}"#), ChildFrame::Other);
        assert_eq!(classify_child(br#"{"type":"assistant","message":{"content":[]}}"#), ChildFrame::Other);
        assert_eq!(classify_child(br#"{"type":"system","subtype":"status"}"#), ChildFrame::Other);
    }

    #[test]
    fn cr_terminated_lines_still_classify() {
        // Lines keep their `\r`; JSON treats it as trailing whitespace.
        assert!(matches!(classify_child(b"{\"type\":\"user\",\"uuid\":\"u1\"}\r"), ChildFrame::User { uuid: Some(u), .. } if u == "u1"));
    }

    #[test]
    fn mirror_frames_keep_raw_entries() {
        let line = br#"{"type":"transcript_mirror","filePath":"/r/p/s.jsonl","entries":[{"z":1,"a":1e21,"s":"\t\"x"},{"b":[1, 2]}]}"#;
        match classify_child(line) {
            ChildFrame::Mirror { file_path, entries } => {
                assert_eq!(file_path.as_deref(), Some("/r/p/s.jsonl"));
                assert!(matches!(file_path, Some(Cow::Borrowed(_))), "an unescaped string is borrowed");
                let got: Vec<&str> = entries.iter().map(|e| e.get()).collect();
                assert_eq!(got, vec![r#"{"z":1,"a":1e21,"s":"\t\"x"}"#, r#"{"b":[1, 2]}"#], "bytes, key order and number format untouched");
            }
            other => panic!("{other:?}"),
        }
        // Malformed mirror frames are still mirror frames (never forwarded).
        assert_eq!(classify_child(br#"{"type":"transcript_mirror"}"#), ChildFrame::Mirror { file_path: None, entries: vec![] });
        assert_eq!(classify_child(br#"{"type":"transcript_mirror","filePath":3,"entries":"x"}"#), ChildFrame::Mirror { file_path: None, entries: vec![] });
    }

    #[test]
    fn init_and_escaped_strings() {
        match classify_child(br#"{"type":"system","subtype":"init","session_id":"s-1","cwd":"/a\/b","tools":[]}"#) {
            ChildFrame::Init { session_id, cwd } => {
                assert_eq!(session_id.as_deref(), Some("s-1"));
                assert_eq!(cwd.as_deref(), Some("/a/b"));
                assert!(matches!(cwd, Some(Cow::Owned(_))), "an escaped string is unescaped into an owned value");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(classify_child(br#"{"type":"system","subtype":"init"}"#), ChildFrame::Init { session_id: None, cwd: None });
    }

    #[test]
    fn control_frames_both_directions() {
        let resp = br#"{"type":"control_response","response":{"subtype":"success","request_id":"abc123","response":{"commands":[]}}}"#;
        assert_eq!(
            classify_child(resp),
            ChildFrame::ControlResponse { request_id: Some("abc123".into()), subtype: Some("success".into()) }
        );
        let req = br#"{"type":"control_request","request_id":"r9","request":{"subtype":"can_use_tool","tool_name":"Bash"}}"#;
        assert_eq!(classify_child(req), ChildFrame::ControlRequest { request_id: Some("r9".into()), subtype: Some("can_use_tool".into()) });
        let host_req = br#"{"request_id":"k2l","type":"control_request","request":{"subtype":"initialize","hooks":{}}}"#;
        match classify_host(host_req) {
            HostFrame::ControlRequest { request_id, subtype, request } => {
                assert_eq!(request_id.as_deref(), Some("k2l"));
                assert_eq!(subtype.as_deref(), Some("initialize"));
                assert_eq!(request.map(RawValue::get), Some(r#"{"subtype":"initialize","hooks":{}}"#));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(classify_host(br#"{"type":"control_cancel_request","request_id":"k2l"}"#), HostFrame::ControlCancel { request_id: Some("k2l".into()) });
        assert_eq!(
            classify_host(br#"{"type":"control_response","response":{"subtype":"success","request_id":"r9","response":{"behavior":"allow"}}}"#),
            HostFrame::ControlResponse { request_id: Some("r9".into()) }
        );
        // A request without a usable id or subtype is still a request.
        assert_eq!(classify_child(br#"{"type":"control_request","request":5}"#), ChildFrame::ControlRequest { request_id: None, subtype: None });
    }

    #[test]
    fn user_frames_and_replay_echoes() {
        assert_eq!(classify_host(br#"{"type":"user","uuid":"u-1","session_id":"","message":{"role":"user","content":"hi"}}"#), HostFrame::User { uuid: Some("u-1".into()) });
        assert_eq!(classify_host(br#"{"type":"user","message":{}}"#), HostFrame::User { uuid: None });
        assert_eq!(
            classify_child(br#"{"type":"user","message":{},"session_id":"s","parent_tool_use_id":null,"uuid":"u-1","isReplay":true,"isSynthetic":false}"#),
            ChildFrame::User { uuid: Some("u-1".into()), is_replay: true }
        );
        assert_eq!(classify_child(br#"{"type":"user","uuid":null,"isReplay":"yes"}"#), ChildFrame::User { uuid: None, is_replay: false }, "wrong types read as absent");
    }

    #[test]
    fn result_frames_and_the_resume_miss() {
        let ok = br#"{"type":"result","subtype":"success","is_error":false,"user_message_uuid":"u2","user_message_uuids":["u1","u2",7]}"#;
        match classify_child(ok) {
            ChildFrame::Result { subtype, is_error, first_error, user_message_uuid, user_message_uuids } => {
                assert_eq!(subtype.as_deref(), Some("success"));
                assert!(!is_error);
                assert_eq!(first_error, None);
                assert_eq!(user_message_uuid.as_deref(), Some("u2"));
                assert_eq!(user_message_uuids, vec![Cow::Borrowed("u1"), Cow::Borrowed("u2")], "non-strings are skipped");
            }
            other => panic!("{other:?}"),
        }
        // The verbatim shape the CLI prints on a resume miss (stdout half).
        let miss = br#"{"type":"result","subtype":"error_during_execution","duration_ms":0,"duration_api_ms":0,"is_error":true,"num_turns":0,"stop_reason":null,"session_id":"9d2f0c7e-1b3a-4c5d-8e6f-7a8b9c0d1e2f","total_cost_usd":0,"usage":{},"modelUsage":{},"permission_denials":[],"uuid":"x","errors":["No conversation found with session ID: 11111111-2222-4333-8444-555555555555"],"result_index":0}"#;
        let frame = classify_child(miss);
        assert!(is_resume_miss(&frame), "{frame:?}");
        let sibling = br#"{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["No message found with message.uuid of: abc"]}"#;
        assert!(!is_resume_miss(&classify_child(sibling)), "the sibling failure has the same shape but another text");
        let not_error = br#"{"type":"result","subtype":"success","is_error":false,"errors":["No conversation found with session ID: x"]}"#;
        assert!(!is_resume_miss(&classify_child(not_error)));
        assert!(!is_resume_miss(&ChildFrame::Other));
    }

    #[test]
    fn state_subtypes() {
        for s in STATE_SUBTYPES {
            assert!(is_state_subtype(s));
        }
        for s in ["initialize", "interrupt", "update_settings", "rewind_files", "mcp_message", "mcp_toggle", "remote_control", ""] {
            assert!(!is_state_subtype(s), "{s}");
        }
        assert!(is_state_subtype(CUMULATIVE_SUBTYPE));
    }

    #[test]
    fn builders_round_trip_through_the_recognisers() {
        let req = raw(r#"{"subtype":"apply_flag_settings","settings":{"model":"m\"1"}}"#);
        let line = control_request_line("0199-fresh", &req);
        match classify_host(&line) {
            HostFrame::ControlRequest { request_id, subtype, request } => {
                assert_eq!(request_id.as_deref(), Some("0199-fresh"));
                assert_eq!(subtype.as_deref(), Some("apply_flag_settings"));
                assert_eq!(request.map(RawValue::get), Some(req.get()), "the request is copied byte-for-byte");
            }
            other => panic!("{other:?}"),
        }
        let ok = control_success_line("o1", &raw(r#"{"accessToken":null}"#));
        assert_eq!(&ok[..], br#"{"type":"control_response","response":{"subtype":"success","request_id":"o1","response":{"accessToken":null}}}"#);
        let err = control_error_line("q\"7", "ai-env-claude: child respawned");
        assert_eq!(classify_child(&err), ChildFrame::ControlResponse { request_id: Some("q\"7".into()), subtype: Some("error".into()) });
        let v: serde_json::Value = serde_json::from_slice(&err).unwrap();
        assert_eq!(v["response"]["error"], "ai-env-claude: child respawned");
    }

    #[test]
    fn rewrite_response_id_is_byte_exact() {
        let line = br#"{"type":"control_response","response":{"subtype":"success","request_id":"0199aa","response":{"z":1,"a":2.50}}}"#;
        let out = rewrite_response_id(line, "0199aa", "orig1").unwrap();
        assert_eq!(&out[..], br#"{"type":"control_response","response":{"subtype":"success","request_id":"orig1","response":{"z":1,"a":2.50}}}"#);
        assert_eq!(rewrite_response_id(line, "missing", "x"), None);
        let twice = br#"{"type":"control_response","response":{"subtype":"success","request_id":"id","response":{"echo":"id"}}}"#;
        assert_eq!(rewrite_response_id(twice, "id", "x"), None, "an ambiguous id is never rewritten");
        let not_response = br#"{"type":"user","uuid":"0199aa"}"#;
        assert_eq!(rewrite_response_id(not_response, "0199aa", "x"), None);
    }
}
