//! The host-state recorder/replayer of the S2 pump: pure bookkeeping over the
//! frames `wire::claude` recognises, no I/O.
//!
//! The extension talks to ONE CLI process per session and sends
//! `initialize` exactly once. When the wrapper has to replace the child (the
//! S2 resume-seed retry; S6 gaps, S10 re-address and migration later), the
//! new child must be brought to the same state without the extension
//! noticing. This module records what the host said, and tells the pump what
//! to replay and which of the new child's frames to hide:
//!
//! * host → child: `initialize` (kept whole), the state requests of
//!   `wire::claude::STATE_SUBTYPES` (last value per `set_*` subtype; every
//!   `apply_flag_settings` in order, since each merges into the CLI's flag
//!   layer), every request id still unanswered (`pending`), and every user
//!   line no forwarded `result` has acknowledged yet (`outstanding`);
//! * a respawn replays `initialize` and the state requests under FRESH
//!   request ids (the caller mints uuid v7s), then re-sends every
//!   outstanding user line verbatim, in send order;
//! * the new child's answer to a fresh id is REWRITTEN to the original id
//!   when the extension is still waiting for that original (the first child
//!   died before answering — the S2 resume-miss path), and SWALLOWED when the
//!   original was already answered;
//! * the new child's first `system/init` is swallowed only when the first
//!   re-sent user line's turn had already started (an init was forwarded
//!   after that line): headless CLIs emit one init per turn, so the new
//!   child's first init belongs to that re-sent turn, whose init the webview
//!   already saw (each init sets `busy` and resets the turn bookkeeping); a
//!   turn that never started, or nothing re-sent, gets its init — as do all
//!   later inits;
//! * an `isReplay` user echo of a re-sent line is swallowed only when an echo
//!   for that uuid was already forwarded — the webview uses the echo to learn
//!   that a message was accepted and to mark the turn start, so an echo it
//!   never saw must reach it;
//! * pending host requests that are not replayed (`interrupt`,
//!   `mcp_message`, a superseded `set_*`, …) are failed towards the host with
//!   an error `control_response` (`fail_in_flight`), so nothing waits forever.
//!
//! Every line crossing this API is WITHOUT its trailing `\n`.
use crate::bridge::registry::HostStateSnapshot;
use crate::wire::claude::{self, ChildFrame, HostFrame, CUMULATIVE_SUBTYPE};
use crate::wire::redact::scrub;
use bytes::Bytes;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// At most this many `apply_flag_settings` requests are kept for a replay;
/// beyond it the two oldest are folded into one (a shallow merge of their
/// `settings` with `null`s kept — exactly what the CLI's flag layer does, so
/// the replayed state is unchanged; the folded entry keeps the newer id).
pub const MAX_CUMULATIVE: usize = 256;

/// The error text sent to the host for a request the respawned child will
/// never answer.
pub const RESPAWN_ERROR: &str = "ai-env-claude: child respawned";

/// The error text sent to the host for a replayed request the new child did
/// not answer before the replay deadline.
pub const REPLAY_TIMEOUT_ERROR: &str = "ai-env-claude: respawned child did not answer";

/// One host request kept for a replay: its subtype, the id the host used,
/// and the raw `request` object (re-sent byte-for-byte under a fresh id).
#[derive(Debug, Clone)]
pub struct Recorded {
    pub subtype: String,
    pub request_id: String,
    pub request: Box<RawValue>,
}

/// A host user line no forwarded `result` has acknowledged yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLine {
    /// The webview-minted uuid (absent on some synthetic sends).
    pub uuid: Option<String>,
    /// The line exactly as the host wrote it (without `\n`).
    pub line: Bytes,
    /// A `system/init` was forwarded after this line (its turn started).
    pub turn_started: bool,
}

/// Why a child frame was hidden from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swallowed {
    /// The new child's answer to a replayed request the host already had.
    ReplayResponse,
    /// The new child's first `system/init` after an init was forwarded.
    SecondInit,
    /// The `isReplay` echo of a re-sent user line whose echo the host already saw.
    UserEcho,
}

/// What the pump does with one child frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildVerdict {
    /// Forward the line unchanged.
    Forward,
    /// Forward this line instead (a replayed answer carrying the original request id).
    Rewritten(Bytes),
    /// Do not forward.
    Swallow(Swallowed),
}

/// The recorder. `HostState::default()` is generation 1 with nothing recorded.
#[derive(Debug)]
pub struct HostState {
    initialize: Option<Recorded>,
    state: Vec<Recorded>,
    /// Host request id → subtype, not yet answered by a child.
    pending: BTreeMap<String, String>,
    outstanding: VecDeque<UserLine>,
    /// Uuids whose `isReplay` echo was forwarded and whose line is still outstanding.
    echoed: BTreeSet<String>,
    /// Every fresh id handed to a child → the original host id it stands for,
    /// `None` when the original was already answered (the answer is swallowed).
    fresh: BTreeMap<String, Option<String>>,
    /// The fresh ids of the open replay window still unanswered.
    window: BTreeSet<String>,
    swallow_init: bool,
    swallow_echo: BTreeSet<String>,
    gen: u32,
    init_seen_this_gen: bool,
    inits_forwarded: u32,
}

impl Default for HostState {
    fn default() -> Self {
        HostState {
            initialize: None,
            state: Vec::new(),
            pending: BTreeMap::new(),
            outstanding: VecDeque::new(),
            echoed: BTreeSet::new(),
            fresh: BTreeMap::new(),
            window: BTreeSet::new(),
            swallow_init: false,
            swallow_echo: BTreeSet::new(),
            gen: 1,
            init_seen_this_gen: false,
            inits_forwarded: 0,
        }
    }
}

fn owned(raw: &RawValue) -> Box<RawValue> {
    // A `&RawValue` from the recognisers is valid JSON by construction.
    RawValue::from_string(raw.get().to_string()).unwrap_or_else(|_| RawValue::from_string("null".to_string()).expect("null is JSON"))
}

/// `newer` with its `settings` replaced by `{...older.settings, ...newer.settings}`
/// (top-level keys only; `null` values kept, as the CLI's merge keeps them
/// to delete keys).
fn merge_flag_requests(older: &RawValue, newer: &RawValue) -> Option<Box<RawValue>> {
    let old: serde_json::Value = serde_json::from_str(older.get()).ok()?;
    let mut new: serde_json::Value = serde_json::from_str(newer.get()).ok()?;
    let mut settings = old.get("settings")?.as_object()?.clone();
    for (k, v) in new.get("settings")?.as_object()? {
        settings.insert(k.clone(), v.clone());
    }
    new["settings"] = serde_json::Value::Object(settings);
    RawValue::from_string(serde_json::to_string(&new).ok()?).ok()
}

fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

impl HostState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one host → child line (always forwarded by the pump).
    pub fn on_host_frame(&mut self, frame: &HostFrame<'_>, line: &[u8]) {
        match frame {
            HostFrame::ControlRequest { request_id, subtype, request } => {
                let sub = subtype.as_deref().unwrap_or("");
                if let Some(id) = request_id {
                    self.pending.insert(id.to_string(), sub.to_string());
                }
                let Some(request) = request else { return };
                let rec = Recorded { subtype: sub.to_string(), request_id: request_id.as_deref().unwrap_or("").to_string(), request: owned(request) };
                if sub == "initialize" {
                    self.initialize = Some(rec);
                } else if sub == CUMULATIVE_SUBTYPE {
                    self.state.push(rec);
                    if self.state.iter().filter(|r| r.subtype == CUMULATIVE_SUBTYPE).count() > MAX_CUMULATIVE {
                        self.fold_oldest_flags();
                    }
                } else if claude::is_state_subtype(sub) {
                    self.state.retain(|r| r.subtype != sub);
                    self.state.push(rec);
                }
            }
            HostFrame::ControlCancel { request_id: Some(id) } => {
                self.pending.remove(id.as_ref());
            }
            HostFrame::User { uuid } => {
                self.outstanding.push_back(UserLine { uuid: uuid.as_deref().map(str::to_string), line: Bytes::copy_from_slice(line), turn_started: false });
            }
            HostFrame::ControlCancel { request_id: None } | HostFrame::ControlResponse { .. } | HostFrame::Other => {}
        }
    }

    /// Fold the two oldest `apply_flag_settings` into one: the older one's
    /// `settings` shallow-merged under the newer one's (nulls kept), at the
    /// newer one's position and id. A request that does not parse is dropped
    /// (it could not be replayed meaningfully either).
    fn fold_oldest_flags(&mut self) {
        let idx: Vec<usize> = self.state.iter().enumerate().filter(|(_, r)| r.subtype == CUMULATIVE_SUBTYPE).map(|(i, _)| i).take(2).collect();
        let [older, newer] = idx[..] else { return };
        match merge_flag_requests(&self.state[older].request, &self.state[newer].request) {
            Some(merged) => self.state[newer].request = merged,
            None => tracing::warn!("an unparseable {CUMULATIVE_SUBTYPE} request was dropped from the replay"),
        }
        self.state.remove(older);
    }

    /// Start a child generation (1 for the first spawn, then 2, 3, …): its
    /// first `system/init` is the one the swallow rule looks at.
    pub fn begin_gen(&mut self, gen: u32) {
        self.gen = gen;
        self.init_seen_this_gen = false;
    }

    /// Decide one child → host frame (mirror frames, the local oauth answer
    /// and the held resume-miss result are the pump's, never passed here).
    pub fn on_child_frame(&mut self, frame: &ChildFrame<'_>, line: &[u8]) -> ChildVerdict {
        match frame {
            ChildFrame::ControlResponse { request_id: Some(id), .. } => {
                let id = id.as_ref();
                if let Some(original) = self.fresh.remove(id) {
                    self.window.remove(id);
                    return match original {
                        Some(orig) if self.pending.remove(&orig).is_some() => match claude::rewrite_response_id(line, id, &orig) {
                            Some(rewritten) => ChildVerdict::Rewritten(rewritten),
                            None => ChildVerdict::Forward,
                        },
                        _ => ChildVerdict::Swallow(Swallowed::ReplayResponse),
                    };
                }
                self.pending.remove(id);
                ChildVerdict::Forward
            }
            ChildFrame::Init { .. } => {
                let first_of_gen = !self.init_seen_this_gen;
                self.init_seen_this_gen = true;
                if first_of_gen && self.gen >= 2 && self.swallow_init {
                    self.swallow_init = false;
                    return ChildVerdict::Swallow(Swallowed::SecondInit);
                }
                self.inits_forwarded += 1;
                // One init per turn: it starts the oldest outstanding turn not yet started.
                if let Some(l) = self.outstanding.iter_mut().find(|l| !l.turn_started) {
                    l.turn_started = true;
                }
                ChildVerdict::Forward
            }
            ChildFrame::User { uuid: Some(u), is_replay: true } => {
                if self.swallow_echo.remove(u.as_ref()) {
                    return ChildVerdict::Swallow(Swallowed::UserEcho);
                }
                if self.outstanding.iter().any(|l| l.uuid.as_deref() == Some(u.as_ref())) {
                    self.echoed.insert(u.to_string());
                }
                ChildVerdict::Forward
            }
            ChildFrame::Result { user_message_uuid, user_message_uuids, .. } => {
                self.retire(user_message_uuid.as_deref(), user_message_uuids);
                // A result means the new child is serving turns: stop holding host input.
                self.window.clear();
                ChildVerdict::Forward
            }
            _ => ChildVerdict::Forward,
        }
    }

    /// Retire acknowledged user lines the way the extension does: the
    /// singular uuid splices everything up to and including it, every uuid of
    /// the plural list is removed, and a result carrying neither retires the
    /// uuid-less lines (they cannot be matched any other way).
    fn retire(&mut self, single: Option<&str>, plural: &[Cow<'_, str>]) {
        let mut gone: Vec<Option<String>> = Vec::new();
        if let Some(u) = single {
            if let Some(pos) = self.outstanding.iter().position(|l| l.uuid.as_deref() == Some(u)) {
                gone.extend(self.outstanding.drain(..=pos).map(|l| l.uuid));
            }
        }
        if !plural.is_empty() {
            let set: BTreeSet<&str> = plural.iter().map(AsRef::as_ref).collect();
            self.outstanding.retain(|l| {
                let hit = l.uuid.as_deref().is_some_and(|u| set.contains(u));
                if hit {
                    gone.push(l.uuid.clone());
                }
                !hit
            });
        }
        if single.is_none() && plural.is_empty() {
            self.outstanding.retain(|l| l.uuid.is_some());
        }
        for u in gone.into_iter().flatten() {
            self.echoed.remove(&u);
            self.swallow_echo.remove(&u);
        }
    }

    /// The lines to write into a freshly spawned child, in order:
    /// `initialize` then the state requests (fresh ids from `fresh_id`), then
    /// every outstanding user line verbatim. Opens the replay window
    /// ([`HostState::replaying`] is true until the child has answered every
    /// fresh id, a `result` arrives, or [`HostState::replay_expired`]).
    /// Call [`HostState::begin_gen`] first and [`HostState::fail_in_flight`] after.
    pub fn replay_lines(&mut self, fresh_id: &mut dyn FnMut() -> String) -> Vec<Bytes> {
        let mut out = Vec::new();
        self.window.clear();
        let requests: Vec<&Recorded> = self.initialize.iter().chain(self.state.iter()).collect();
        for rec in requests {
            let id = fresh_id();
            let original = (!rec.request_id.is_empty() && self.pending.contains_key(&rec.request_id)).then(|| rec.request_id.clone());
            out.push(claude::control_request_line(&id, &rec.request));
            self.fresh.insert(id.clone(), original);
            self.window.insert(id);
        }
        self.swallow_echo = self.outstanding.iter().filter_map(|l| l.uuid.clone()).filter(|u| self.echoed.contains(u)).collect();
        out.extend(self.outstanding.iter().map(|l| l.line.clone()));
        self.swallow_init = self.outstanding.front().is_some_and(|l| l.turn_started);
        out
    }

    /// Error `control_response`s (to the host) for every pending host request
    /// no replayed request stands for, which the new child will therefore
    /// never answer; they leave `pending`.
    pub fn fail_in_flight(&mut self) -> Vec<Bytes> {
        let covered: BTreeSet<String> = self.fresh.values().flatten().cloned().collect();
        let failed: Vec<String> = self.pending.keys().filter(|id| !covered.contains(*id)).cloned().collect();
        failed
            .into_iter()
            .map(|id| {
                self.pending.remove(&id);
                claude::control_error_line(&id, RESPAWN_ERROR)
            })
            .collect()
    }

    /// The replay deadline passed: stop holding host input, and fail every
    /// original the new child has not answered yet (a late answer is then
    /// swallowed). Returns the error lines for the host.
    pub fn replay_expired(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        for id in std::mem::take(&mut self.window) {
            if let Some(slot) = self.fresh.get_mut(&id) {
                if let Some(orig) = slot.take() {
                    if self.pending.remove(&orig).is_some() {
                        out.push(claude::control_error_line(&orig, REPLAY_TIMEOUT_ERROR));
                    }
                }
            }
        }
        out
    }

    /// Is a replay window open (the pump holds host input meanwhile)?
    #[must_use]
    pub fn replaying(&self) -> bool {
        !self.window.is_empty()
    }

    #[must_use]
    pub fn gen(&self) -> u32 {
        self.gen
    }

    /// How many `system/init` frames were forwarded to the host.
    #[must_use]
    pub fn inits_forwarded(&self) -> u32 {
        self.inits_forwarded
    }

    /// The host's `initialize` request id, once recorded.
    #[must_use]
    pub fn initialize_id(&self) -> Option<&str> {
        self.initialize.as_ref().map(|r| r.request_id.as_str()).filter(|s| !s.is_empty())
    }

    #[must_use]
    pub fn outstanding(&self) -> &VecDeque<UserLine> {
        &self.outstanding
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The recorded requests in replay order (initialize first).
    #[must_use]
    pub fn recorded(&self) -> Vec<&Recorded> {
        self.initialize.iter().chain(self.state.iter()).collect()
    }

    /// What the registry keeps: digests and an allowlisted summary, never a
    /// request body.
    #[must_use]
    pub fn snapshot(&self) -> HostStateSnapshot {
        let mut snap = HostStateSnapshot::default();
        if let Some(init) = &self.initialize {
            snap.initialize_sha256 = Some(digest(init.request.get()));
            snap.initialize_bytes = Some(init.request.get().len() as u64);
        }
        let mut flag_keys: BTreeSet<String> = BTreeSet::new();
        for rec in &self.state {
            let text = rec.request.get();
            snap.recorded.insert(rec.subtype.clone(), format!("sha256:{}:{}", digest(text), text.len()));
            let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { continue };
            let s = |x: &serde_json::Value| x.as_str().map(|t| scrub(t).into_owned());
            match rec.subtype.as_str() {
                "set_permission_mode" => snap.permission_mode = s(&v["mode"]),
                "set_model" => snap.model = s(&v["model"]),
                "set_max_thinking_tokens" => snap.max_thinking_tokens = v["max_thinking_tokens"].as_u64(),
                "mcp_set_servers" => {
                    snap.mcp_server_names = v["servers"].as_object().map(|m| m.keys().map(|k| scrub(k).into_owned()).collect()).unwrap_or_default();
                }
                CUMULATIVE_SUBTYPE => {
                    if let Some(settings) = v["settings"].as_object() {
                        flag_keys.extend(settings.keys().map(|k| scrub(k).into_owned()));
                        if let Some(model) = settings.get("model") {
                            snap.model = s(model);
                        }
                    }
                }
                _ => {}
            }
        }
        snap.flag_keys = flag_keys.into_iter().collect();
        snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::claude::{classify_child, classify_host};

    fn host(st: &mut HostState, line: &str) {
        st.on_host_frame(&classify_host(line.as_bytes()), line.as_bytes());
    }

    fn child(st: &mut HostState, line: &str) -> ChildVerdict {
        st.on_child_frame(&classify_child(line.as_bytes()), line.as_bytes())
    }

    fn ids() -> impl FnMut() -> String {
        let mut n = 0;
        move || {
            n += 1;
            format!("fresh-{n}")
        }
    }

    const INIT: &str = r#"{"request_id":"i1","type":"control_request","request":{"subtype":"initialize","hooks":{"PreToolUse":[]}}}"#;
    const PERM: &str = r#"{"request_id":"p1","type":"control_request","request":{"subtype":"set_permission_mode","mode":"acceptEdits"}}"#;
    const FLAGS: &str = r#"{"request_id":"f1","type":"control_request","request":{"subtype":"apply_flag_settings","settings":{"viewMode":"focus"}}}"#;
    const MODEL: &str = r#"{"request_id":"f2","type":"control_request","request":{"subtype":"apply_flag_settings","settings":{"model":"claude-x"}}}"#;
    const USER1: &str = r#"{"type":"user","uuid":"u1","session_id":"","message":{"role":"user","content":"one"}}"#;
    const USER2: &str = r#"{"type":"user","uuid":"u2","session_id":"","message":{"role":"user","content":"two"}}"#;

    fn resp(id: &str) -> String {
        format!(r#"{{"type":"control_response","response":{{"subtype":"success","request_id":"{id}","response":{{}}}}}}"#)
    }

    fn result(uuid: &str) -> String {
        format!(r#"{{"type":"result","subtype":"success","is_error":false,"user_message_uuid":"{uuid}","user_message_uuids":["{uuid}"]}}"#)
    }

    fn texts(lines: &[Bytes]) -> Vec<String> {
        lines.iter().map(|b| String::from_utf8(b.to_vec()).unwrap()).collect()
    }

    #[test]
    fn records_initialize_and_state_in_order_with_last_value_per_set_subtype() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        host(&mut st, PERM);
        host(&mut st, FLAGS);
        host(&mut st, &PERM.replace("p1", "p2").replace("acceptEdits", "plan"));
        host(&mut st, MODEL);
        let rec: Vec<(&str, &str)> = st.recorded().iter().map(|r| (r.subtype.as_str(), r.request_id.as_str())).collect();
        assert_eq!(rec, vec![("initialize", "i1"), ("apply_flag_settings", "f1"), ("set_permission_mode", "p2"), ("apply_flag_settings", "f2")]);
        assert_eq!(st.initialize_id(), Some("i1"));
        assert_eq!(st.pending_len(), 5, "every host request is pending until answered");
    }

    #[test]
    fn non_state_requests_are_pending_but_not_recorded_and_cancel_clears_pending() {
        let mut st = HostState::new();
        host(&mut st, r#"{"request_id":"x1","type":"control_request","request":{"subtype":"interrupt"}}"#);
        host(&mut st, r#"{"request_id":"x2","type":"control_request","request":{"subtype":"update_settings","scope":"localSettings"}}"#);
        assert!(st.recorded().is_empty());
        assert_eq!(st.pending_len(), 2);
        host(&mut st, r#"{"type":"control_cancel_request","request_id":"x1"}"#);
        assert_eq!(st.pending_len(), 1);
        assert_eq!(child(&mut st, &resp("x2")), ChildVerdict::Forward);
        assert_eq!(st.pending_len(), 0);
    }

    #[test]
    fn outstanding_user_lines_are_retired_like_the_extension_does() {
        let mut st = HostState::new();
        host(&mut st, USER1);
        host(&mut st, USER2);
        host(&mut st, r#"{"type":"user","message":{}}"#);
        assert_eq!(st.outstanding().len(), 3);
        // The singular uuid splices everything up to and including it.
        assert_eq!(child(&mut st, r#"{"type":"result","user_message_uuid":"u2"}"#), ChildVerdict::Forward);
        assert_eq!(st.outstanding().len(), 1, "u1 and u2 retired");
        // A result with neither field retires the uuid-less lines.
        child(&mut st, r#"{"type":"result","subtype":"success"}"#);
        assert!(st.outstanding().is_empty());
        // The plural list removes its members wherever they are.
        host(&mut st, USER1);
        host(&mut st, USER2);
        child(&mut st, r#"{"type":"result","user_message_uuids":["u2"]}"#);
        assert_eq!(st.outstanding().iter().map(|l| l.uuid.clone().unwrap()).collect::<Vec<_>>(), vec!["u1"]);
    }

    #[test]
    fn respawn_after_death_before_answering_rewrites_the_initialize_answer() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        host(&mut st, PERM);
        host(&mut st, MODEL);
        host(&mut st, USER1);
        // Generation 1 died without answering anything.
        st.begin_gen(2);
        let mut fresh = ids();
        let lines = texts(&st.replay_lines(&mut fresh));
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains(r#""request_id":"fresh-1""#) && lines[0].contains(r#""subtype":"initialize","hooks":{"PreToolUse":[]}"#), "{}", lines[0]);
        assert!(lines[1].contains("fresh-2") && lines[1].contains("acceptEdits"));
        assert!(lines[2].contains("fresh-3") && lines[2].contains("claude-x"));
        assert_eq!(lines[3], USER1, "user lines are re-sent verbatim");
        assert!(st.replaying());
        assert!(st.fail_in_flight().is_empty(), "every pending original is covered by a replay");
        // The new child's answers carry the original ids.
        match child(&mut st, &resp("fresh-1")) {
            ChildVerdict::Rewritten(b) => assert_eq!(String::from_utf8(b.to_vec()).unwrap(), resp("i1")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(child(&mut st, &resp("fresh-2")), ChildVerdict::Rewritten(_)));
        assert!(st.replaying());
        assert!(matches!(child(&mut st, &resp("fresh-3")), ChildVerdict::Rewritten(_)));
        assert!(!st.replaying(), "every fresh id answered: the window closes");
        assert_eq!(st.pending_len(), 0);
        // No init was ever forwarded: the new child's init passes, and so does its echo.
        assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Forward);
        assert_eq!(child(&mut st, r#"{"type":"user","uuid":"u1","isReplay":true}"#), ChildVerdict::Forward, "the host never saw an echo for u1");
    }

    #[test]
    fn respawn_after_a_live_session_swallows_what_the_host_already_saw() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        assert_eq!(child(&mut st, &resp("i1")), ChildVerdict::Forward);
        host(&mut st, USER1);
        // Headless CLIs emit the init of a turn after its user input.
        assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Forward);
        assert!(st.outstanding()[0].turn_started);
        assert_eq!(child(&mut st, r#"{"type":"user","uuid":"u1","isReplay":true}"#), ChildVerdict::Forward);
        // A second, in-flight request that the new child will not replay.
        host(&mut st, r#"{"request_id":"m1","type":"control_request","request":{"subtype":"mcp_message","server_name":"x"}}"#);
        st.begin_gen(2);
        let lines = texts(&st.replay_lines(&mut ids()));
        assert_eq!(lines.len(), 2, "initialize + the outstanding user line");
        let failed = texts(&st.fail_in_flight());
        assert_eq!(failed.len(), 1);
        assert!(failed[0].contains(r#""request_id":"m1""#) && failed[0].contains(RESPAWN_ERROR), "{}", failed[0]);
        assert_eq!(child(&mut st, &resp("fresh-1")), ChildVerdict::Swallow(Swallowed::ReplayResponse));
        assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Swallow(Swallowed::SecondInit));
        assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Forward, "only the first init of the new child");
        assert_eq!(child(&mut st, r#"{"type":"user","uuid":"u1","isReplay":true}"#), ChildVerdict::Swallow(Swallowed::UserEcho));
        assert_eq!(child(&mut st, r#"{"type":"user","uuid":"u1","isReplay":true}"#), ChildVerdict::Forward, "swallowed exactly once");
        assert_eq!(child(&mut st, &result("u1")), ChildVerdict::Forward);
        assert!(st.outstanding().is_empty());
    }

    #[test]
    fn a_re_sent_turn_that_never_started_gets_its_init() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        child(&mut st, &resp("i1"));
        host(&mut st, USER1);
        child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#);
        child(&mut st, &result("u1"));
        // The next line was sent but the child died before its turn started.
        host(&mut st, USER2);
        assert!(!st.outstanding()[0].turn_started);
        st.begin_gen(2);
        st.replay_lines(&mut ids());
        assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Forward, "the webview never saw this turn start");
    }

    #[test]
    fn every_outstanding_line_is_re_sent_in_send_order() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        host(&mut st, USER1);
        host(&mut st, r#"{"type":"keep_alive"}"#);
        host(&mut st, USER2);
        st.begin_gen(2);
        let lines = texts(&st.replay_lines(&mut ids()));
        assert_eq!(lines[1..], [USER1.to_string(), USER2.to_string()], "both lines, in send order, verbatim");
    }

    #[test]
    fn with_nothing_re_sent_the_new_childs_first_init_starts_a_new_turn_and_passes() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        child(&mut st, &resp("i1"));
        host(&mut st, USER1);
        child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#);
        child(&mut st, &result("u1"));
        st.begin_gen(2);
        st.replay_lines(&mut ids());
        assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Forward, "the next turn's init");
    }

    #[test]
    fn inits_of_the_first_generation_always_pass() {
        let mut st = HostState::new();
        for _ in 0..3 {
            assert_eq!(child(&mut st, r#"{"type":"system","subtype":"init","session_id":"s"}"#), ChildVerdict::Forward);
        }
        assert_eq!(st.inits_forwarded(), 3);
    }

    #[test]
    fn replay_expiry_fails_unanswered_originals_and_swallows_late_answers() {
        let mut st = HostState::new();
        host(&mut st, INIT);
        st.begin_gen(2);
        st.replay_lines(&mut ids());
        let errs = texts(&st.replay_expired());
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains(r#""request_id":"i1""#) && errs[0].contains(REPLAY_TIMEOUT_ERROR));
        assert!(!st.replaying());
        assert_eq!(child(&mut st, &resp("fresh-1")), ChildVerdict::Swallow(Swallowed::ReplayResponse), "a late answer is hidden");
    }

    #[test]
    fn a_result_closes_the_window_and_nothing_to_replay_opens_none() {
        let mut st = HostState::new();
        st.begin_gen(2);
        assert!(st.replay_lines(&mut ids()).is_empty());
        assert!(!st.replaying());
        host(&mut st, INIT);
        st.begin_gen(3);
        st.replay_lines(&mut ids());
        assert!(st.replaying());
        child(&mut st, r#"{"type":"result","subtype":"success"}"#);
        assert!(!st.replaying());
    }

    #[test]
    fn apply_flag_settings_fold_beyond_the_cap_without_changing_the_merged_state() {
        let mut st = HostState::new();
        host(&mut st, r#"{"request_id":"a0","type":"control_request","request":{"subtype":"apply_flag_settings","settings":{"model":"m1","viewMode":"focus"}}}"#);
        host(&mut st, r#"{"request_id":"a1","type":"control_request","request":{"subtype":"apply_flag_settings","settings":{"viewMode":null,"effortLevel":"high"}}}"#);
        for i in 2..MAX_CUMULATIVE + 2 {
            host(&mut st, &FLAGS.replace("f1", &format!("a{i}")).replace("focus", &format!("v{i}")));
        }
        let rec = st.recorded();
        assert_eq!(rec.len(), MAX_CUMULATIVE, "two entries were folded into one");
        assert_eq!(rec[0].request_id, "a2", "the fold sits at the newer entry's place with its id");
        let v: serde_json::Value = serde_json::from_str(rec[0].request.get()).unwrap();
        assert_eq!(v["settings"]["model"], "m1", "keys only the oldest set survive");
        assert_eq!(v["settings"]["effortLevel"], "high");
        assert_eq!(v["settings"]["viewMode"], "v2", "the newest value wins");
        assert_eq!(v["subtype"], "apply_flag_settings");
        // A null that deletes a key survives a fold.
        let folded = merge_flag_requests(
            &RawValue::from_string(r#"{"subtype":"apply_flag_settings","settings":{"a":1}}"#.into()).unwrap(),
            &RawValue::from_string(r#"{"subtype":"apply_flag_settings","settings":{"a":null,"b":2}}"#.into()).unwrap(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(folded.get()).unwrap();
        assert!(v["settings"]["a"].is_null() && v["settings"].as_object().unwrap().contains_key("a"));
        assert_eq!(v["settings"]["b"], 2);
    }

    #[test]
    fn snapshot_keeps_digests_and_a_summary_never_bodies() {
        let mut st = HostState::new();
        let secret = format!("sk-ant-oat01-{}", "Q".repeat(24));
        let servers = format!(r#"{{"request_id":"s1","type":"control_request","request":{{"subtype":"mcp_set_servers","servers":{{"github":{{"type":"stdio","command":"x","env":{{"OPENAI_API_KEY":"{secret}"}}}}}}}}}}"#);
        host(&mut st, INIT);
        host(&mut st, PERM);
        host(&mut st, &servers);
        host(&mut st, FLAGS);
        host(&mut st, MODEL);
        host(&mut st, r#"{"request_id":"t1","type":"control_request","request":{"subtype":"set_max_thinking_tokens","max_thinking_tokens":8000,"thinking_display":null}}"#);
        let snap = st.snapshot();
        assert_eq!(snap.permission_mode.as_deref(), Some("acceptEdits"));
        assert_eq!(snap.model.as_deref(), Some("claude-x"));
        assert_eq!(snap.max_thinking_tokens, Some(8000));
        assert_eq!(snap.mcp_server_names, vec!["github"]);
        assert_eq!(snap.flag_keys, vec!["model", "viewMode"]);
        assert!(snap.initialize_sha256.as_deref().is_some_and(|h| h.len() == 64));
        assert!(snap.recorded["mcp_set_servers"].starts_with("sha256:"));
        let toml = toml::to_string(&snap).unwrap();
        assert!(!toml.contains(&secret) && !toml.contains("OPENAI_API_KEY") && !toml.contains("command"), "{toml}");
    }

    #[test]
    fn replayed_state_requests_are_byte_identical_to_the_recorded_ones() {
        let mut st = HostState::new();
        let odd = r#"{"request_id":"f9","type":"control_request","request":{"subtype":"apply_flag_settings","settings":{"z":1,"a":2.50,"s":"x\"y"}}}"#;
        host(&mut st, odd);
        st.begin_gen(2);
        let lines = texts(&st.replay_lines(&mut ids()));
        assert!(lines[0].ends_with(r#""request":{"subtype":"apply_flag_settings","settings":{"z":1,"a":2.50,"s":"x\"y"}}}"#), "{}", lines[0]);
    }
}
