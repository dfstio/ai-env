//! Recognisers for the Claude stream-json frames the wrapper must act on,
//! builders for the few frames it writes itself, and the byte-exact edits it
//! makes to forwarded ones (a response's id, the `initialize` answer's pid).
//! Pure and serde-only: the S2 pump (`bridge::pump`, `bridge::hoststate`) and
//! the S8 remote session use them.
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
//!
//! S10 (plans/s10-contracts.md §3.2) reads three more, each forwarded as
//! [`ChildFrame::Other`] was (only the pump's bookkeeping looks at them):
//! * child → host `{"type":"assistant","uuid":…,"parent_tool_use_id":…,…}`
//!   (top level when `parent_tool_use_id` is absent or `null`): the leaf a
//!   moved CLI resumes at;
//! * `{"type":"keep_alive"}` both ways (dropped while a session is parked);
//! * child → host `{"type":"control_cancel_request","request_id":…}`: the
//!   CLI withdraws its own request.
//!
//! And it writes two lines to the host: the move's informational note
//! ([`informational_line`]) and the withdrawal of a dead CLI's request
//! ([`control_cancel_line`]).
//!
//! S10 addendum A1 reads one more, forwarded as [`ChildFrame::Other`] was:
//! child → host `{"type":"rate_limit_event","rate_limit_info":{…},…}`, its
//! info kept raw for the pump's usage tap (`wire::ratelimit` reads it).
//!
//! S12 (T) reads one more child frame, forwarded as `Other` was:
//! `system`/`session_title_changed`, and the title of an answer the pump knows
//! to be one ([`title_answer`]; plans/s12-contracts.md §T1.2): child → host
//! `{"type":"system","subtype":"session_title_changed","title":<t>,"uuid":…,"session_id":<sid>}`
//! ([`ChildFrame::TitleChanged`]), and `response.response.title` of the success
//! answer to a host `generate_session_title`. Every other `system` subtype stays
//! [`ChildFrame::Other`]. Phase 4 (§T3 P2 as amended): the `title` of the host's
//! own `rename_session` request ([`rename_request_title`]), read only to tell the
//! CLI's echo of it from its startup frame, never kept as a title itself.
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

/// S12 (T): the CLI's name for the session, as a `system` frame:
/// `{"type":"system","subtype":"session_title_changed","title":<t>,"uuid":<u>,"session_id":<sid>}`, at its
/// start when the session has a name and after each rename (none for a generated title, none for an empty one).
pub const SESSION_TITLE_CHANGED: &str = "session_title_changed";
/// S12 (T): the host's request whose success answer carries the chat's title (`response.response.title`).
pub const GENERATE_TITLE_SUBTYPE: &str = "generate_session_title";
/// S12 (T, phase 4): the host's rename of the chat (2.1.310's
/// `{"subtype":"rename_session","title":<t>,"source":"host","session_id":<sid>}`), which the CLI echoes as a
/// [`SESSION_TITLE_CHANGED`] frame naming `<t>`.
pub const RENAME_SESSION_SUBTYPE: &str = "rename_session";

/// The CLI's resume-miss text; in stream-json mode it is printed on stderr
/// AND carried as `errors[0]` of an `error_during_execution` result on stdout.
pub const RESUME_MISS_MARKER: &str = "No conversation found with session ID:";

/// S10: the CLI's cut-miss text (`--resume-session-at=<uuid>` names no
/// message of the transcript), carried as a resume miss's is.
pub const CUT_MISS_MARKER: &str = "No message found with message.uuid of:";

/// S11 (A.5): how the CLI (commander) refuses an option it does not know, on stderr, before it reads stdin:
/// `error: unknown option '--x'` (or `'--x=value'`), a suggestion sometimes after it.
pub const UNKNOWN_OPTION_MARKER: &str = "error: unknown option '";

/// The longest name [`unknown_option`] takes after `--`.
const OPTION_NAME_MAX: usize = 64;

/// The long option an unknown-option line names, without its `=value`: the first line of `stderr` that starts,
/// after leading blanks, with [`UNKNOWN_OPTION_MARKER`], whose quoted name is `--[A-Za-z0-9][A-Za-z0-9-]{0,63}`
/// before an optional `=…` and the closing quote. `None` for anything else (a short option, a longer name, no
/// closing quote, another text).
#[must_use]
pub fn unknown_option(stderr: &str) -> Option<String> {
    let line = stderr.lines().find_map(|l| l.trim_start().strip_prefix(UNKNOWN_OPTION_MARKER))?;
    let body = line.strip_prefix("--")?;
    let name_len = body.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'-').count();
    let (name, rest) = body.split_at(name_len);
    if name.is_empty() || name_len > OPTION_NAME_MAX || !name.as_bytes()[0].is_ascii_alphanumeric() {
        return None;
    }
    let closed = match rest.as_bytes().first() {
        Some(b'\'') => true,
        Some(b'=') => rest[1..].contains('\''),
        _ => false,
    };
    closed.then(|| format!("--{name}"))
}

/// S11 (A.1): a text the code relies on, which a version's Linux binary must hold before it is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VMarker {
    /// Its name in records and audit rows: a code word, never the text.
    pub name: &'static str,
    /// The forms, any one of which counts (a bundle keeps some texts escaped), searched as bytes.
    pub forms: &'static [&'static str],
}

/// The texts an admitted version must hold (A §1.6): the Dockerfile's strings gate's four, in its order; the
/// resume miss; the usage limit's two (`rate_limit_resets` in its UTF-8 form and its two escaped ones, LD-39); the
/// four values `wire::managed::MANAGED_HARDENING` sets, by their last keys; the unknown option.
pub const V_MARKERS: [VMarker; 12] = [
    VMarker { name: "resume_session_at", forms: &["--resume-session-at"] },
    VMarker { name: "cut_miss", forms: &[CUT_MISS_MARKER] },
    VMarker { name: "session_id", forms: &["--session-id"] },
    VMarker { name: "in_use", forms: &["is already in use"] },
    VMarker { name: "resume_miss", forms: &[RESUME_MISS_MARKER] },
    VMarker { name: "rate_limit_hit", forms: &[crate::wire::ratelimit::HIT] },
    VMarker { name: "rate_limit_resets", forms: &[crate::wire::ratelimit::RESETS, " \\xB7 resets ", " \\u00B7 resets "] },
    VMarker { name: "bypass_mode", forms: &["disableBypassPermissionsMode"] },
    VMarker { name: "auto_mode", forms: &["disableAutoMode"] },
    VMarker { name: "autoupdater", forms: &["DISABLE_AUTOUPDATER"] },
    VMarker { name: "updates", forms: &["DISABLE_UPDATES"] },
    VMarker { name: "unknown_option", forms: &[UNKNOWN_OPTION_MARKER] },
];

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
    /// S10: an `assistant` frame; `top_level` when its `parent_tool_use_id`
    /// is absent or `null` (not a subagent's).
    Assistant { uuid: Option<Cow<'a, str>>, top_level: bool },
    /// S10: `keep_alive`.
    KeepAlive,
    /// S10: `control_cancel_request` from the CLI: it withdraws its own request.
    ControlCancel { request_id: Option<Cow<'a, str>> },
    /// A1: `rate_limit_event`; `info` its `rate_limit_info`, raw.
    RateLimit { info: Option<&'a RawValue> },
    /// S12 (T): `system`/`session_title_changed`, forwarded untouched (the pump reads it).
    TitleChanged { session_id: Option<Cow<'a, str>>, title: Option<Cow<'a, str>> },
    /// Everything else (`stream_event`, other `system` subtypes, non-JSON
    /// noise): forwarded untouched.
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
    /// S10: `keep_alive`.
    KeepAlive,
    /// Everything else (non-JSON, other types): forwarded untouched.
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
            (F::Assistant { uuid: a, top_level: x }, F::Assistant { uuid: b, top_level: y }) => a == b && x == y,
            (F::ControlCancel { request_id: a }, F::ControlCancel { request_id: b }) => a == b,
            (F::RateLimit { info: a }, F::RateLimit { info: b }) => a.map(RawValue::get) == b.map(RawValue::get),
            (F::TitleChanged { session_id: a, title: x }, F::TitleChanged { session_id: b, title: y }) => a == b && x == y,
            (F::KeepAlive, F::KeepAlive) | (F::Other, F::Other) => true,
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
            (H::KeepAlive, H::KeepAlive) | (H::Other, H::Other) => true,
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
    /// `None` when absent or `null` (serde reads a `null` option as none).
    #[serde(borrow, default)]
    parent_tool_use_id: Option<&'a RawValue>,
    #[serde(borrow, default)]
    rate_limit_info: Option<&'a RawValue>,
    #[serde(borrow, default)]
    title: Option<&'a RawValue>,
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
        "system" if text(p.subtype).as_deref() == Some(SESSION_TITLE_CHANGED) => ChildFrame::TitleChanged { session_id: text(p.session_id), title: text(p.title) },
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
        "assistant" => ChildFrame::Assistant { uuid: text(p.uuid), top_level: p.parent_tool_use_id.is_none() },
        "keep_alive" => ChildFrame::KeepAlive,
        "control_cancel_request" => ChildFrame::ControlCancel { request_id: text(p.request_id) },
        "rate_limit_event" => ChildFrame::RateLimit { info: p.rate_limit_info },
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
        "keep_alive" => HostFrame::KeepAlive,
        _ => HostFrame::Other,
    }
}

/// Is `subtype` recorded as session state (see [`STATE_SUBTYPES`])?
#[must_use]
pub fn is_state_subtype(subtype: &str) -> bool {
    STATE_SUBTYPES.contains(&subtype)
}

/// The CLI's resume-miss result: an error `result` whose first error starts
/// with [`RESUME_MISS_MARKER`]. The sibling print-path failures (the cut
/// miss, [`CUT_MISS_MARKER`]; the drop-guard refusal) share the frame
/// shape, so the text decides, never the shape.
#[must_use]
pub fn is_resume_miss(frame: &ChildFrame<'_>) -> bool {
    matches!(frame, ChildFrame::Result { is_error: true, first_error: Some(e), .. } if e.starts_with(RESUME_MISS_MARKER))
}

/// S10: the CLI's cut miss: an error `result` whose first error starts with
/// [`CUT_MISS_MARKER`] (`--resume-session-at` named a message the transcript
/// lacks). Told by its text, as a resume miss is.
#[must_use]
pub fn is_cut_miss(frame: &ChildFrame<'_>) -> bool {
    matches!(frame, ChildFrame::Result { is_error: true, first_error: Some(e), .. } if e.starts_with(CUT_MISS_MARKER))
}

/// S12 (T): the title of a success `control_response` (`response.response.title`, a string), unescaped;
/// `None` for an error answer, a `null`, missing or non-string title, a title anywhere else in the line, and
/// any other line. Read leniently, as [`rewrite_initialize_pid`] reads its pid.
///
/// Which answer is one is the pump's to know (the host's request it answers was a
/// [`GENERATE_TITLE_SUBTYPE`], `HostState::pending_subtype`): this reads the line alone, never a request's body.
#[must_use]
pub fn title_answer(line: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Line<'a> {
        #[serde(borrow, default)]
        response: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Answer<'a> {
        #[serde(borrow, default)]
        title: Option<&'a RawValue>,
    }
    if !matches!(classify_child(line), ChildFrame::ControlResponse { subtype: Some(s), .. } if s == "success") {
        return None;
    }
    let outer = serde_json::from_slice::<Line<'_>>(line).ok()?.response?;
    let answer = serde_json::from_str::<Line<'_>>(outer.get()).ok()?.response?;
    let title = serde_json::from_str::<Answer<'_>>(answer.get()).ok()?.title;
    text(title).map(Cow::into_owned)
}

/// S12 (T, phase 4): the `title` of the host's [`RENAME_SESSION_SUBTYPE`] request (`request.title`, a string),
/// unescaped; `None` for a request of another subtype, a `null`, missing or non-string title, a title anywhere else
/// in the line, and any other line. Read leniently, as [`title_answer`] reads its answer.
///
/// The pump reads it only to tell the CLI's echo of the host's own rename (a `session_title_changed` with that text)
/// from the CLI's startup frame (§T3 P2 as amended in phase 4); the title it keeps is still the echo's, never this.
#[must_use]
pub fn rename_request_title(line: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Request<'a> {
        #[serde(borrow, default)]
        title: Option<&'a RawValue>,
    }
    let HostFrame::ControlRequest { subtype: Some(subtype), request: Some(request), .. } = classify_host(line) else { return None };
    if subtype != RENAME_SESSION_SUBTYPE {
        return None;
    }
    let title = serde_json::from_str::<Request<'_>>(request.get()).ok()?.title;
    text(title).map(Cow::into_owned)
}

/// A JSON string literal for `s` (quotes and escapes included).
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// S10 (L3): the note the pump writes to the host only, never to a child
/// and never into the transcript:
/// `{"type":"system","subtype":"informational","level":"warning","content":<text>,"session_id":<sid>,"uuid":<uuid>}`,
/// `session_id` left out when `None`. The caller mints `uuid` (a fresh uuid
/// v7). The extension shows it as a line of the chat when `level` is not
/// `info` and the chat already has content.
#[must_use]
pub fn informational_line(text: &str, session_id: Option<&str>, uuid: &str) -> Bytes {
    let sid = session_id.map(|s| format!(",\"session_id\":{}", json_str(s))).unwrap_or_default();
    Bytes::from(format!("{{\"type\":\"system\",\"subtype\":\"informational\",\"level\":\"warning\",\"content\":{}{sid},\"uuid\":{}}}", json_str(text), json_str(uuid)))
}

/// S10 (L4): `{"type":"control_cancel_request","request_id":<id>}` for the
/// host: a request of a CLI that is gone is withdrawn (the extension
/// dismisses its prompt).
#[must_use]
pub fn control_cancel_line(request_id: &str) -> Bytes {
    Bytes::from(format!("{{\"type\":\"control_cancel_request\",\"request_id\":{}}}", json_str(request_id)))
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

/// The CLI's answer to `initialize` with the pid it reports
/// (`response.response.pid`) made `to`, every other byte unchanged, and the
/// pid it reported (S8 §4): the extension takes that pid for the process it
/// spawned, which is the wrapper's, never the CLI's in a VM or a respawned
/// generation's. `None` unless the line is a success `control_response`
/// whose inner `pid` serde reads as an integer P, and `"pid":P` not followed
/// by a digit occurs exactly once in the line, and the rewritten line reads
/// back with the inner pid `to`; the caller then forwards the line unchanged.
#[must_use]
pub fn rewrite_initialize_pid(line: &[u8], to: u32) -> Option<(Bytes, u64)> {
    #[derive(Deserialize)]
    struct Line<'a> {
        #[serde(borrow, default)]
        response: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Pid {
        pid: u64,
    }
    fn inner_pid(line: &[u8]) -> Option<u64> {
        let outer = serde_json::from_slice::<Line<'_>>(line).ok()?.response?;
        let answer = serde_json::from_str::<Line<'_>>(outer.get()).ok()?.response?;
        serde_json::from_str::<Pid>(answer.get()).ok().map(|p| p.pid)
    }
    if !matches!(classify_child(line), ChildFrame::ControlResponse { subtype: Some(s), .. } if s == "success") {
        return None;
    }
    let pid = inner_pid(line)?;
    let needle = format!("\"pid\":{pid}");
    let hits: Vec<usize> = line.windows(needle.len()).enumerate().filter(|(at, w)| *w == needle.as_bytes() && !line.get(at + needle.len()).is_some_and(u8::is_ascii_digit)).map(|(at, _)| at).collect();
    let &[at] = hits.as_slice() else { return None };
    let mut out = Vec::with_capacity(line.len() + 10);
    out.extend_from_slice(&line[..at]);
    out.extend_from_slice(format!("\"pid\":{to}").as_bytes());
    out.extend_from_slice(&line[at + needle.len()..]);
    // The one occurrence must have been the inner pid (not a nested one while the inner is spelled otherwise).
    (inner_pid(&out) == Some(u64::from(to))).then(|| (Bytes::from(out), pid))
}

/// A child `control_response` line with `response.request_id` changed from
/// `from` to `to`, everything else byte-for-byte: the one quoted occurrence
/// of `from` is replaced (the pump's replay ids are fresh uuid v7s, unique in
/// the line). `None` when `from` does not occur exactly once — the caller
/// then forwards the line unchanged.
#[must_use]
/// The JSON string `from` (quoted, so only a whole string value matches) in
/// `line` as `to`, at most `max` times present, or `None` when it is absent,
/// present more often, or the line is not UTF-8. Part B (22 Oct): a move's
/// resent user line goes out under a fresh uuid (claude skips a line whose
/// uuid its session already holds), and the new CLI's frames come back under
/// the original ([`crate::bridge::hoststate::HostState::restore_resent`]).
pub fn swap_json_str(line: &[u8], from: &str, to: &str, max: usize) -> Option<Bytes> {
    let hay = std::str::from_utf8(line).ok()?;
    let needle = json_str(from);
    let n = hay.matches(needle.as_str()).count();
    if n == 0 || n > max {
        return None;
    }
    Some(Bytes::from(hay.replace(needle.as_str(), &json_str(to))))
}

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
        assert_eq!(classify_child(br#"{"type":"system","subtype":"status"}"#), ChildFrame::Other);
        assert_eq!(classify_child(br#"{"type":"stream_event","event":{}}"#), ChildFrame::Other);
    }

    /// S10 (§3.2): `assistant`, `keep_alive` and the CLI's own
    /// `control_cancel_request` classify; an assistant frame is top level
    /// when its `parent_tool_use_id` is absent or `null`; a field of the
    /// wrong type reads as absent; the host's `keep_alive` too.
    #[test]
    fn assistant_keep_alive_and_cancel_frames_classify() {
        let top = br#"{"type":"assistant","message":{"role":"assistant","content":[]},"parent_tool_use_id":null,"session_id":"s","uuid":"a-1"}"#;
        assert_eq!(classify_child(top), ChildFrame::Assistant { uuid: Some("a-1".into()), top_level: true });
        assert_eq!(classify_child(br#"{"type":"assistant","message":{"content":[]}}"#), ChildFrame::Assistant { uuid: None, top_level: true }, "absent: top level");
        let sub = br#"{"type":"assistant","message":{},"parent_tool_use_id":"toolu_01","uuid":"a-2"}"#;
        assert_eq!(classify_child(sub), ChildFrame::Assistant { uuid: Some("a-2".into()), top_level: false }, "a subagent's");
        assert_eq!(classify_child(br#"{"type":"assistant","uuid":7}"#), ChildFrame::Assistant { uuid: None, top_level: true }, "a uuid of the wrong type reads as absent");
        assert_eq!(classify_child(br#"{"type":"keep_alive"}"#), ChildFrame::KeepAlive);
        assert_eq!(classify_host(br#"{"type":"keep_alive"}"#), HostFrame::KeepAlive);
        assert_eq!(classify_child(br#"{"type":"control_cancel_request","request_id":"perm-1-1"}"#), ChildFrame::ControlCancel { request_id: Some("perm-1-1".into()) });
        assert_eq!(classify_child(br#"{"type":"control_cancel_request"}"#), ChildFrame::ControlCancel { request_id: None });
        assert_ne!(classify_child(br#"{"type":"keep_alive"}"#), ChildFrame::Other, "no longer Other");
        assert_ne!(ChildFrame::Assistant { uuid: None, top_level: true }, ChildFrame::Assistant { uuid: None, top_level: false });
    }

    /// A1: `rate_limit_event` classifies with its info kept raw (B16's
    /// trimmed line, the constructed full one), compared by its text; one
    /// with no info has none; the host never sends one (`Other` there).
    #[test]
    fn a_rate_limit_event_classifies_with_its_raw_info() {
        let b16 = include_str!("../../tests/fixtures/claude/valid-stream-json-2.1.296.jsonl").lines().find(|l| l.contains("rate_limit_event")).unwrap();
        let ChildFrame::RateLimit { info: Some(info) } = classify_child(b16.as_bytes()) else { panic!("not a rate limit: {b16}") };
        assert_eq!(info.get(), r#"{"status":"allowed"}"#);
        // The constructed 2.1.305 line, inlined (S11, C §C.7.1: C6 replaces the constructed fixture by a real one).
        let full = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1792663200,"rateLimitType":"seven_day","utilization":0.81,"unifiedWindows":{"five_hour":{"utilization":0.23,"resetsAt":1792591200},"seven_day":{"utilization":0.81,"resetsAt":1792663200}},"overageStatus":"allowed","isUsingOverage":true,"surpassedThreshold":0.75},"uuid":"00000000-0000-4000-8000-000000000001","session_id":"00000000-0000-4000-8000-0000000000a1"}"#;
        let ChildFrame::RateLimit { info: Some(info) } = classify_child(full.as_bytes()) else { panic!("not a rate limit: {full}") };
        assert!(info.get().starts_with(r#"{"status":"allowed_warning","#) && info.get().contains("unifiedWindows"), "{}", info.get());
        assert_eq!(classify_child(br#"{"type":"rate_limit_event"}"#), ChildFrame::RateLimit { info: None });
        let a = raw(r#"{"status":"allowed"}"#);
        let b = raw(r#"{"status":"rejected"}"#);
        assert_eq!(ChildFrame::RateLimit { info: Some(&a) }, ChildFrame::RateLimit { info: Some(&raw(r#"{"status":"allowed"}"#)) });
        assert_ne!(ChildFrame::RateLimit { info: Some(&a) }, ChildFrame::RateLimit { info: Some(&b) });
        assert_ne!(ChildFrame::RateLimit { info: None }, ChildFrame::Other);
        assert_eq!(classify_host(b16.as_bytes()), HostFrame::Other);
    }

    /// S11 (A.5): the long option an unknown-option line names, without its
    /// value, from the first such line (after leading blanks, a suggestion
    /// after it); never a short option, a name past 64 characters, an
    /// unclosed quote or another text.
    #[test]
    fn unknown_option_names_the_long_flag() {
        let cases: [(&str, Option<&str>); 16] = [
            ("error: unknown option '--x'", Some("--x")),
            ("error: unknown option '--thinking-display'\n", Some("--thinking-display")),
            ("error: unknown option '--effort=high'", Some("--effort")),
            ("error: unknown option '--effort=it's'", Some("--effort")),
            ("warn: something\n  error: unknown option '--new-flag' (Did you mean --new-flags?)\n", Some("--new-flag")),
            ("error: unknown option '--a1-b'\nerror: unknown option '--second'", Some("--a1-b")),
            ("error: unknown option '-x'", None),
            ("error: unknown option '--'", None),
            ("error: unknown option '---x'", None),
            ("error: unknown option '--x", None),
            ("error: unknown option '--x=v", None),
            ("error: unknown option '--x y'", None),
            ("error: unknown option '--x_y'", None),
            ("error: unknown command 'x'", None),
            ("", None),
            ("error: too many arguments. Expected 0 arguments but got 1.", None),
        ];
        for (stderr, want) in cases {
            assert_eq!(unknown_option(stderr).as_deref(), want, "{stderr:?}");
        }
        let longest = format!("error: unknown option '--{}'", "a".repeat(64));
        assert_eq!(unknown_option(&longest).map(|f| f.len()), Some(66));
        assert_eq!(unknown_option(&format!("error: unknown option '--{}'", "a".repeat(65))), None, "a longer name");
        assert!(UNKNOWN_OPTION_MARKER.ends_with('\''));
    }

    /// S11 (A §1.6): the markers' names are unique code words; the first four
    /// are the Dockerfile's strings gate (its `for want in` line, in order),
    /// the managed four `MANAGED_HARDENING`'s last keys, in order; the
    /// others are the code's own constants.
    #[test]
    fn the_markers_hold_the_dockerfile_gate_and_the_code_constants() {
        let names: std::collections::BTreeSet<&str> = V_MARKERS.iter().map(|m| m.name).collect();
        assert_eq!(names.len(), V_MARKERS.len(), "unique names");
        for m in V_MARKERS {
            assert!(!m.forms.is_empty() && m.forms.iter().all(|f| !f.is_empty()), "{}", m.name);
            assert!(m.name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{}", m.name);
        }
        let docker = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/Dockerfile")).unwrap();
        let gate = docker.lines().find(|l| l.contains("for want in")).expect("the Dockerfile's strings gate");
        let wants: Vec<&str> = gate.split_once("for want in").unwrap().1.split('\'').skip(1).step_by(2).collect();
        assert_eq!(wants, V_MARKERS[..4].iter().map(|m| m.forms[0]).collect::<Vec<_>>(), "{gate}");
        let managed: Vec<&str> = crate::wire::managed::MANAGED_HARDENING.iter().map(|(path, _)| *path.last().unwrap()).collect();
        assert_eq!(managed, V_MARKERS[7..11].iter().map(|m| m.forms[0]).collect::<Vec<_>>());
        let by_name = |n: &str| V_MARKERS.iter().find(|m| m.name == n).unwrap().forms;
        assert_eq!(by_name("cut_miss"), [CUT_MISS_MARKER]);
        assert_eq!(by_name("resume_miss"), [RESUME_MISS_MARKER]);
        assert_eq!(by_name("rate_limit_hit"), [crate::wire::ratelimit::HIT]);
        assert_eq!(by_name("rate_limit_resets"), [crate::wire::ratelimit::RESETS, " \\xB7 resets ", " \\u00B7 resets "]);
        assert_eq!(by_name("rate_limit_resets")[1].len(), 13, "the four ASCII characters of the escape");
        assert_eq!(by_name("rate_limit_resets")[2].len(), 15, "the six of the other");
        assert_eq!(by_name("unknown_option"), [UNKNOWN_OPTION_MARKER]);
    }

    /// The two lines S10's pump writes to the host, byte for byte: the
    /// informational note (with and without a session id, its text escaped)
    /// and the withdrawal of a request, which reads back as the CLI's own
    /// cancel. The note is `Other` to the pump: it is never bookkept.
    #[test]
    fn the_informational_and_cancel_lines_are_byte_exact() {
        let uuid = "0199f0e1-0000-7000-8000-000000000001";
        let note = informational_line("ai-env: the chat continues on microvm-1", Some("11111111-2222-4333-8444-555555555555"), uuid);
        assert_eq!(
            &note[..],
            br#"{"type":"system","subtype":"informational","level":"warning","content":"ai-env: the chat continues on microvm-1","session_id":"11111111-2222-4333-8444-555555555555","uuid":"0199f0e1-0000-7000-8000-000000000001"}"#
        );
        let bare = informational_line("a \"quoted\"\nline", None, uuid);
        assert_eq!(&bare[..], br#"{"type":"system","subtype":"informational","level":"warning","content":"a \"quoted\"\nline","uuid":"0199f0e1-0000-7000-8000-000000000001"}"#);
        let v: serde_json::Value = serde_json::from_slice(&bare).unwrap();
        assert_eq!((v["content"].as_str(), v.get("session_id")), (Some("a \"quoted\"\nline"), None));
        assert_eq!(classify_child(&note), ChildFrame::Other);
        let cancel = control_cancel_line("perm-1-1");
        assert_eq!(&cancel[..], br#"{"type":"control_cancel_request","request_id":"perm-1-1"}"#);
        assert_eq!(classify_child(&cancel), ChildFrame::ControlCancel { request_id: Some("perm-1-1".into()) });
        assert_eq!(classify_host(&cancel), HostFrame::ControlCancel { request_id: Some("perm-1-1".into()) });
        assert_eq!(&control_cancel_line("q\"7")[..], br#"{"type":"control_cancel_request","request_id":"q\"7"}"#);
    }

    /// A cut miss (`--resume-session-at` naming a message the transcript
    /// lacks) and a resume miss share the result's shape: the text tells
    /// them apart, and neither is the other.
    #[test]
    fn a_cut_miss_is_told_by_its_text() {
        let cut = br#"{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["No message found with message.uuid of: 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"]}"#;
        let resume = br#"{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["No conversation found with session ID: 11111111-2222-4333-8444-555555555555"]}"#;
        assert!(is_cut_miss(&classify_child(cut)) && !is_resume_miss(&classify_child(cut)));
        assert!(is_resume_miss(&classify_child(resume)) && !is_cut_miss(&classify_child(resume)));
        let not_error = br#"{"type":"result","subtype":"success","is_error":false,"errors":["No message found with message.uuid of: x"]}"#;
        assert!(!is_cut_miss(&classify_child(not_error)), "only an error result");
        let later = br#"{"type":"result","is_error":true,"errors":["boom","No message found with message.uuid of: x"]}"#;
        assert!(!is_cut_miss(&classify_child(later)), "only the first error counts");
        assert!(!is_cut_miss(&ChildFrame::Other));
        assert_eq!(CUT_MISS_MARKER, "No message found with message.uuid of:");
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

    /// The `initialize` answer the CLI prints (claude 2.1.296's shape: the
    /// inner response's keys, the pid last), its pid made the wrapper's,
    /// every other byte as it was; the pid it reported comes back.
    #[test]
    fn the_initialize_pid_is_rewritten_byte_exact() {
        let line = br#"{"type":"control_response","response":{"subtype":"success","request_id":"k2l","response":{"commands":[{"name":"compact","description":"Clear history but keep a summary","argumentHint":"<optional>"}],"output_style":"default","available_output_styles":["default","Explanatory","Learning"],"models":[{"value":"default","displayName":"Default (recommended)"}],"account":{"subscriptionType":"max"},"pid":48213}}}"#;
        let (out, from) = rewrite_initialize_pid(line, 777).unwrap();
        assert_eq!(from, 48213);
        let want = String::from_utf8_lossy(line).replace("\"pid\":48213", "\"pid\":777");
        assert_eq!(&out[..], want.as_bytes(), "only the digits changed");
        assert_eq!(classify_child(&out), ChildFrame::ControlResponse { request_id: Some("k2l".into()), subtype: Some("success".into()) });
        // The fake claude's answer, the pid alone; the same pid is a no-op that still answers.
        let fake = br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid":4242}}}"#;
        assert_eq!(rewrite_initialize_pid(fake, 9).map(|(b, p)| (b.to_vec(), p)), Some((br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid":9}}}"#.to_vec(), 4242)));
        assert_eq!(rewrite_initialize_pid(fake, 4242).map(|(b, p)| (b.to_vec(), p)), Some((fake.to_vec(), 4242)));
        // A longer pid in a nested object is not the inner one: `"pid":42` followed by a digit is no occurrence.
        let nested = br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"mcp":{"pid":4210},"pid":42}}}"#;
        let (out, from) = rewrite_initialize_pid(nested, 5).unwrap();
        assert_eq!((String::from_utf8_lossy(&out).into_owned(), from), (r#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"mcp":{"pid":4210},"pid":5}}}"#.to_string(), 42));
    }

    /// Whenever the inner pid cannot be found once, byte-exact, nothing is
    /// rewritten (the caller forwards the line as it came): no pid, a pid
    /// that is no integer, a pid spelled with a space, the same `"pid":P`
    /// twice (a nested copy, a string that ends in it never counts), an
    /// error answer, another frame, a pid only in a nested object.
    #[test]
    fn an_initialize_answer_whose_pid_is_not_found_once_passes_unchanged() {
        for line in [
            &br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"commands":[]}}}"#[..],
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid":"4242"}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid":-1}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid":42.5}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid": 4242}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"child":{"pid":4242},"pid":4242}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid":4242,"child":{"pid":4242}}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"pid": 4242,"child":{"pid":4242}}}}"#,
            br#"{"type":"control_response","response":{"subtype":"error","request_id":"i1","error":"no","response":{"pid":4242}}}"#,
            br#"{"type":"system","subtype":"init","response":{"response":{"pid":4242}}}"#,
            br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"child":{"pid":4242}}}}"#,
            b"not json \"pid\":4242",
        ] {
            assert_eq!(rewrite_initialize_pid(line, 9), None, "{}", String::from_utf8_lossy(line));
        }
        // A string ending in the needle is escaped in JSON, so it never matches.
        let quoted = br#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{"note":"\"pid\":4242","pid":4242}}}"#;
        assert!(rewrite_initialize_pid(quoted, 9).is_some_and(|(b, _)| b.ends_with(br#""pid":9}}}"#)));
    }

    /// S12 (T, §T1.2): 2.1.310's `session_title_changed` classifies with its session and title, borrowed
    /// unless escaped (an escape is unescaped: a U+202E reaches the pump, which cleans it); a title or a
    /// session id of the wrong type, `null` or absent reads as absent; two titles fail the peek (`Other`, as
    /// two of any peeked key do); the frame equals itself and its clone and no other frame; every other
    /// `system` subtype stays `Other` (R's `session_state_changed` included); the host never sends it.
    #[test]
    fn a_title_frame_classifies_and_equals_itself() {
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let line = format!(r#"{{"type":"system","subtype":"session_title_changed","title":"Harbour-s11 word memory","uuid":"00000000-0000-4000-5000-000000000001","session_id":"{sid}"}}"#);
        let frame = classify_child(line.as_bytes());
        let ChildFrame::TitleChanged { session_id, title } = &frame else { panic!("not a title frame: {frame:?}") };
        assert_eq!((session_id.as_deref(), title.as_deref()), (Some(sid), Some("Harbour-s11 word memory")));
        assert!(matches!(title, Some(Cow::Borrowed(_))) && matches!(session_id, Some(Cow::Borrowed(_))), "unescaped strings are borrowed");
        assert_eq!(frame, frame.clone());
        assert_eq!(frame, classify_child(line.as_bytes()));
        assert_ne!(frame, ChildFrame::Other);
        assert_ne!(frame, ChildFrame::Init { session_id: Some(sid.into()), cwd: None });
        assert_ne!(frame, ChildFrame::TitleChanged { session_id: Some(sid.into()), title: Some("another".into()) });
        let bidi = classify_child(br#"{"type":"system","subtype":"session_title_changed","title":"a\u202eb","session_id":"s"}"#);
        let ChildFrame::TitleChanged { title: Some(t), .. } = &bidi else { panic!("{bidi:?}") };
        assert!(matches!(t, Cow::Owned(_)) && t == "a\u{202e}b", "{t:?}");
        for (odd, want_sid, want_title) in [
            (r#"{"type":"system","subtype":"session_title_changed","title":7,"session_id":"s"}"#, Some("s"), None),
            (r#"{"type":"system","subtype":"session_title_changed","title":null,"session_id":"s"}"#, Some("s"), None),
            (r#"{"type":"system","subtype":"session_title_changed","title":"t"}"#, None, Some("t")),
            (r#"{"type":"system","subtype":"session_title_changed","title":"t","session_id":5}"#, None, Some("t")),
        ] {
            assert_eq!(classify_child(odd.as_bytes()), ChildFrame::TitleChanged { session_id: want_sid.map(Cow::Borrowed), title: want_title.map(Cow::Borrowed) }, "{odd}");
        }
        assert_eq!(classify_child(br#"{"type":"system","subtype":"session_title_changed","title":"a","title":"b","session_id":"s"}"#), ChildFrame::Other, "two titles");
        assert_eq!(classify_child(br#"{"type":"system","subtype":"session_state_changed","state":"idle"}"#), ChildFrame::Other, "R's frame stays Other");
        assert_eq!(classify_child(br#"{"type":"system","subtype":"status","title":"x"}"#), ChildFrame::Other);
        assert_eq!(classify_host(line.as_bytes()), HostFrame::Other);
    }

    /// S12 (T, §T1.2): an answer's title is `response.response.title` of a success `control_response`, a
    /// string (an escape unescaped); a `null`, missing or non-string title, an error answer holding one, a
    /// title nested deeper or one level up, another frame's and a line that is no JSON are none.
    #[test]
    fn the_title_answer_is_read_from_a_success_response_only() {
        let answer = |inner: &str| format!(r#"{{"type":"control_response","response":{{"subtype":"success","request_id":"g1","response":{inner}}}}}"#);
        assert_eq!(title_answer(answer(r#"{"title":"Fix the seed"}"#).as_bytes()).as_deref(), Some("Fix the seed"));
        assert_eq!(title_answer(answer(r#"{"title":"\u00e9"}"#).as_bytes()).as_deref(), Some("é"), "an escape, unescaped");
        for none in [
            answer(r#"{"title":null}"#),
            answer("{}"),
            answer(r#"{"title":3}"#),
            answer(r#"{"x":{"title":"decoy"}}"#),
            answer(r#""Fix the seed""#),
            r#"{"type":"control_response","response":{"subtype":"error","request_id":"g1","error":"no","response":{"title":"Fix the seed"}}}"#.to_string(),
            r#"{"type":"control_response","response":{"subtype":"success","request_id":"g1","title":"decoy","response":{}}}"#.to_string(),
            r#"{"type":"system","subtype":"session_title_changed","title":"Fix the seed","session_id":"s"}"#.to_string(),
            "not json".to_string(),
        ] {
            assert_eq!(title_answer(none.as_bytes()), None, "{none}");
        }
    }

    /// S12 (T, phase 4): the host's `rename_session` title, as 2.1.310 sends it, unescaped; nothing of another
    /// request, of a title elsewhere in the line, or of one that is no string.
    #[test]
    fn the_rename_requests_title_is_read_from_a_rename_session_only() {
        let rename = |inner: &str| format!(r#"{{"type":"control_request","request_id":"r1","request":{{"subtype":"rename_session",{inner}"source":"host","session_id":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"}}}}"#);
        assert_eq!(rename_request_title(rename(r#""title":"Harbour-s12 renamed","#).as_bytes()).as_deref(), Some("Harbour-s12 renamed"));
        assert_eq!(rename_request_title(rename(r#""title":"caf\u00e9","#).as_bytes()).as_deref(), Some("café"), "an escape, unescaped");
        for none in [
            rename(r#""title":null,"#),
            rename(""),
            rename(r#""title":7,"#),
            r#"{"type":"control_request","request_id":"g1","request":{"subtype":"generate_session_title","title":"decoy","description":"prompt"}}"#.to_string(),
            r#"{"type":"control_request","request_id":"r1","title":"decoy","request":{"subtype":"rename_session"}}"#.to_string(),
            r#"{"type":"system","subtype":"session_title_changed","title":"decoy","session_id":"s"}"#.to_string(),
            "not json".to_string(),
        ] {
            assert_eq!(rename_request_title(none.as_bytes()), None, "{none}");
        }
    }
}
