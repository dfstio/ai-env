//! S10 §D: an idle remote chat parks. The pump judges the host state after
//! each line it forwards ([`verdict`]) and tells the live session
//! ([`QuietState`], through `remote::link::LinkFactory::quiet`); a session
//! with a [`ParkCtl`] (`agent::run_spawn_parked`) asks the shim to park its
//! spawn once it was quiet for [`ParkPolicy::after`] (the frames `park`,
//! `parked`, `park_refused`, `unpark` of the `park_v1` capability), and stops
//! its pings and keep-alives meanwhile, so the VM may idle into its suspend
//! while the chat stays open.
//!
//! Phase 0 builds the verdict, the policy and the types; the session half is
//! S10 wave 1b's (P), the pump and link halves its C's. The thresholds of
//! §13 ([`CPU_BUSY_MS`], [`MIN_QUIET_S`], [`HOLD_OUTPUT`],
//! [`DROP_HOST_KEEP_ALIVE`]) are B0's (20 Oct 2026, plans/s10-measurements.md):
//! `CPU_BUSY_MS` 300, the other three phase 0's values kept.
use crate::bridge::config::BridgeConfig;
use crate::bridge::hoststate::HostState;
use crate::bridge::lab::VmKnobs;
use crate::bridge::vm::registry::VmRow;
use std::time::Duration;

/// After `unpark` (with its `ping`) the socket counts as lost when neither a
/// `pong` nor a `stdin_ack` came within this.
pub const UNPARK_PROBE: Duration = Duration::from_secs(3);
/// How long the session waits for the shim's answer to a `park`; no answer
/// counts the socket as lost.
pub const PARK_ANSWER_WAIT: Duration = Duration::from_secs(10);
/// At most one `session_park_refused` audit row per session this often.
pub const PARK_REFUSED_LOG_EVERY: Duration = Duration::from_secs(600);
/// What the park grace adds to the VM's wall left ([`ParkPolicy::from_cfg`]).
pub const PARK_GRACE_PAD_S: u32 = 3600;
/// The CPU of the spawn's session per `ACTIVITY_SAMPLE` (10 s) above which
/// the shim calls it busy and refuses the park, in ms; sent as `park.cpu_busy_ms` (§13, B0).
/// B0 (20 Oct 2026, claude 2.1.302): at rest claude used at most 50 ms at a
/// pending prompt and 70 ms after a turn in any sample; a turn runs far above.
pub const CPU_BUSY_MS: u32 = 300;
/// The shim's busy check looks back this far; sent as `park.min_quiet_s` (§13, B0).
pub const MIN_QUIET_S: u32 = 30;
/// Whether a parked spawn's stdout is held in its window instead of sent;
/// sent as `park.hold_output` (§13, B0).
pub const HOLD_OUTPUT: bool = false;
/// While parked, the pump drops the host's `keep_alive` lines (counted in
/// the census's `ka_dropped`) instead of forwarding them (L10, §13, B0).
pub const DROP_HOST_KEEP_ALIVE: bool = true;

/// CLI requests that wait on the user, so a session may park on them.
pub const USER_WAIT: [&str; 1] = ["can_use_tool"];

/// D1's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No outstanding user line, no pending request either way.
    Idle,
    /// At least one outstanding line, no pending host request, and at least one open CLI request, every one in `USER_WAIT`.
    Prompt,
    /// Anything else. An outstanding line with no CLI request open is a turn at work (a quiet tool run too): `Busy`.
    Busy,
}

/// D1's verdict over the host state: what the pump forwarded either way,
/// as `HostState` recorded it.
#[must_use]
pub fn verdict(state: &HostState) -> Verdict {
    let outstanding = !state.outstanding().is_empty();
    let host_pending = state.pending_len() > 0;
    let cli = state.child_requests();
    match (outstanding, host_pending, cli.is_empty()) {
        (false, false, true) => Verdict::Idle,
        (true, false, false) if cli.values().all(|subtype| USER_WAIT.contains(&subtype.as_str())) => Verdict::Prompt,
        _ => Verdict::Busy,
    }
}

/// What the pump tells the live session after each line it forwarded (`LinkFactory::quiet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietState {
    pub verdict: Verdict,
    /// The last forwarded line other than a `keep_alive`, either way (the pump's clock).
    pub since: tokio::time::Instant,
    /// The last forwarded host frame's kind: `user`, `control_response`, `control_request`, `control_cancel_request`, `other`.
    pub last_host: Option<&'static str>,
}

/// The park's timers and thresholds for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParkPolicy {
    /// Quiet this long before a park: the lab knob, else `VmCfg::park_after`.
    pub after: Duration,
    pub grace_s: u32,
    pub min_quiet_s: u32,
    pub cpu_busy_ms: u32,
    pub hold_output: bool,
    /// `UNPARK_PROBE` and `PARK_ANSWER_WAIT`, scaled by `AI_ENV_BRIDGE_LAB_BACKOFF_MS` as `RunPolicy::from_cfg` scales.
    pub probe: Duration,
    pub answer_wait: Duration,
}

impl ParkPolicy {
    /// The policy of a session on the VM of `row`, at `now` (unix seconds).
    /// `grace_s`: the row's `wall_left` plus [`PARK_GRACE_PAD_S`], at least
    /// `DETACH_GRACE_SESSION_S`, at most `PARK_GRACE_MAX_S` (a row with no
    /// wall yet: the most). `after`: `AI_ENV_BRIDGE_LAB_PARK_AFTER_MS` (debug
    /// builds), else `[vm].park_after_s`, else `[vm].max_idle_s`.
    #[must_use]
    pub fn from_cfg(cfg: &BridgeConfig, row: &VmRow, knobs: &VmKnobs, now: u64) -> ParkPolicy {
        use crate::wire::frame::{DETACH_GRACE_SESSION_S, PARK_GRACE_MAX_S};
        let left = row.wall_left(now).unwrap_or(i64::from(PARK_GRACE_MAX_S));
        let grace = left.saturating_add(i64::from(PARK_GRACE_PAD_S)).clamp(i64::from(DETACH_GRACE_SESSION_S), i64::from(PARK_GRACE_MAX_S));
        let scale = |d: Duration| knobs.backoff_ms.map_or(d, |ms| Duration::from_millis(u64::try_from(d.as_millis()).unwrap_or(u64::MAX).saturating_mul(ms) / 1000).max(Duration::from_millis(1)));
        ParkPolicy {
            after: knobs.park_after.unwrap_or_else(|| cfg.vm.park_after()),
            grace_s: u32::try_from(grace).unwrap_or(PARK_GRACE_MAX_S),
            // Scaled as the probe is (whole seconds), so offline tests park a real wrapper quickly.
            min_quiet_s: knobs.backoff_ms.map_or(MIN_QUIET_S, |_| u32::try_from(scale(Duration::from_secs(u64::from(MIN_QUIET_S))).as_secs()).unwrap_or(MIN_QUIET_S)),
            cpu_busy_ms: CPU_BUSY_MS,
            hold_output: HOLD_OUTPUT,
            probe: scale(UNPARK_PROBE),
            answer_wait: scale(PARK_ANSWER_WAIT),
        }
    }
}

/// What a parking session is handed (`agent::run_spawn_parked`).
pub struct ParkCtl {
    pub quiet: tokio::sync::watch::Receiver<QuietState>,
    /// The generation's code-out trigger: a park waits for `quiet()`.
    pub trigger: crate::bridge::codeout::TriggerWatch,
    pub policy: ParkPolicy,
    /// This wrapper, as every `park` names it (`registry::process_identity` of its own pid, read once).
    pub owner: crate::wire::frame::ParkOwner,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::claude::{classify_child, classify_host};

    fn host(st: &mut HostState, line: &str) {
        let _ = st.on_host_frame(&classify_host(line.as_bytes()), line.as_bytes());
    }

    fn child(st: &mut HostState, line: &str) {
        let _ = st.on_child_frame(&classify_child(line.as_bytes()), line.as_bytes());
    }

    const USER: &str = r#"{"type":"user","uuid":"u1","message":{"role":"user","content":"one"}}"#;
    const ASK: &str = r#"{"type":"control_request","request_id":"perm-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"}}}"#;
    const HOOK: &str = r#"{"type":"control_request","request_id":"hook-1","request":{"subtype":"hook_callback","callback_id":"c"}}"#;
    const RESULT: &str = r#"{"type":"result","subtype":"success","is_error":false,"user_message_uuid":"u1","user_message_uuids":["u1"]}"#;

    /// D1: nothing outstanding and nothing pending is idle; an outstanding
    /// line with no CLI request open is a turn at work (busy, a quiet tool
    /// run too); one with an open `can_use_tool` and nothing else is a
    /// prompt; any other open CLI request, or a pending host request, is busy.
    #[test]
    fn the_verdict_is_idle_prompt_or_busy() {
        let mut st = HostState::new();
        assert_eq!(verdict(&st), Verdict::Idle, "a fresh session");
        host(&mut st, USER);
        assert_eq!(verdict(&st), Verdict::Busy, "an outstanding line, no CLI request open: a turn at work");
        child(&mut st, ASK);
        assert_eq!(verdict(&st), Verdict::Prompt, "an open can_use_tool and nothing else");
        child(&mut st, HOOK);
        assert_eq!(verdict(&st), Verdict::Busy, "another CLI request open beside it");
        host(&mut st, r#"{"type":"control_response","response":{"subtype":"success","request_id":"hook-1","response":{}}}"#);
        assert_eq!(verdict(&st), Verdict::Prompt, "the hook answered: the prompt alone again");
        host(&mut st, r#"{"request_id":"i1","type":"control_request","request":{"subtype":"interrupt"}}"#);
        assert_eq!(verdict(&st), Verdict::Busy, "a pending host request");
        child(&mut st, r#"{"type":"control_response","response":{"subtype":"success","request_id":"i1","response":{}}}"#);
        host(&mut st, r#"{"type":"control_response","response":{"subtype":"success","request_id":"perm-1","response":{"behavior":"allow"}}}"#);
        assert_eq!(verdict(&st), Verdict::Busy, "the turn runs on after the answer");
        child(&mut st, RESULT);
        assert_eq!(verdict(&st), Verdict::Idle, "the result retired the line");
        // A CLI request open with no outstanding line is no prompt.
        child(&mut st, ASK.replace("perm-1", "perm-2").as_str());
        assert_eq!(verdict(&st), Verdict::Busy);
        assert_eq!(USER_WAIT, ["can_use_tool"]);
    }

    /// The park grace is the VM's wall left plus an hour, at least the
    /// session's detach grace and at most the 8 h wall plus an hour (a row
    /// with no wall yet gets the most); the timers are the constants, scaled
    /// by the backoff knob as the session's are; `after` is the lab knob's,
    /// else `[vm].park_after_s`, else `[vm].max_idle_s`.
    #[test]
    fn the_park_grace_is_the_wall_left_capped() {
        use crate::wire::frame::{DETACH_GRACE_SESSION_S, PARK_GRACE_MAX_S};
        let now = 1_790_000_000;
        let cfg = BridgeConfig::default();
        let row = |left: Option<i64>| VmRow { wall_deadline: left.map(|l| u64::try_from(i64::try_from(now).unwrap() + l).unwrap()), ..VmRow::default() };
        let grace = |left: Option<i64>| ParkPolicy::from_cfg(&cfg, &row(left), &VmKnobs::default(), now).grace_s;
        assert_eq!(grace(Some(7200)), 7200 + PARK_GRACE_PAD_S);
        assert_eq!(grace(Some(28_800)), PARK_GRACE_MAX_S, "the 8 h wall plus an hour");
        assert_eq!(grace(Some(100_000)), PARK_GRACE_MAX_S, "capped");
        assert_eq!(grace(Some(-60)), PARK_GRACE_PAD_S - 60, "a wall just passed: what the pad leaves");
        assert_eq!(grace(Some(-10_000)), DETACH_GRACE_SESSION_S, "at least the session's detach grace");
        assert_eq!(grace(None), PARK_GRACE_MAX_S, "no wall recorded yet");
        assert_eq!((PARK_GRACE_MAX_S, PARK_GRACE_PAD_S, DETACH_GRACE_SESSION_S), (32_400, 3600, 900));
        let p = ParkPolicy::from_cfg(&cfg, &row(Some(600)), &VmKnobs::default(), now);
        assert_eq!(p, ParkPolicy { after: Duration::from_secs(300), grace_s: 4200, min_quiet_s: MIN_QUIET_S, cpu_busy_ms: CPU_BUSY_MS, hold_output: HOLD_OUTPUT, probe: UNPARK_PROBE, answer_wait: PARK_ANSWER_WAIT });
        let knobs = VmKnobs { backoff_ms: Some(10), park_after: Some(Duration::from_millis(250)), ..VmKnobs::default() };
        let fast = ParkPolicy::from_cfg(&cfg, &row(Some(600)), &knobs, now);
        assert_eq!((fast.after, fast.probe, fast.answer_wait, fast.min_quiet_s), (Duration::from_millis(250), Duration::from_millis(30), Duration::from_millis(100), 0));
        let mut set = BridgeConfig::default();
        set.vm.park_after_s = Some(60);
        assert_eq!(ParkPolicy::from_cfg(&set, &row(Some(600)), &VmKnobs::default(), now).after, Duration::from_secs(60));
        assert_eq!((UNPARK_PROBE, PARK_ANSWER_WAIT, PARK_REFUSED_LOG_EVERY), (Duration::from_secs(3), Duration::from_secs(10), Duration::from_secs(600)));
        assert_eq!((CPU_BUSY_MS, MIN_QUIET_S, HOLD_OUTPUT, DROP_HOST_KEEP_ALIVE), (300, 30, false, true), "§13's values, B0's (20 Oct)");
    }

    /// S12 (R2-8 to R2-10, a control): the CLI's `session_state_changed` frames (the extension sets
    /// `CLAUDE_CODE_SDK_READS_SESSION_STATE`, the wrapper forwards it) are `system` frames of no subtype the pump
    /// reads: each classifies as `ChildFrame::Other` (T's `TitleChanged` takes `session_title_changed` alone), is
    /// forwarded unchanged, and leaves the verdict to the frames around it: `idle` on a fresh state is idle, a
    /// turn's `running` busy, `requires_action` then its `can_use_tool` a prompt, `running` with that ask still open
    /// a prompt still, and the answer, the result, then `idle` idle again.
    #[test]
    fn session_state_frames_never_change_the_verdict() {
        use crate::bridge::hoststate::ChildVerdict;
        use crate::wire::claude::ChildFrame;
        let state = |s: &str, n: u64| format!(r#"{{"type":"system","subtype":"session_state_changed","state":"{s}","sdk_host_only":true,"uuid":"{n:08x}-0000-4000-3000-000000000001","session_id":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"}}"#);
        let (running, requires_action, idle) = (state("running", 1), state("requires_action", 2), state("idle", 4));
        for line in [&running, &requires_action, &idle] {
            assert_eq!(classify_child(line.as_bytes()), ChildFrame::Other, "{line}");
            assert_eq!(HostState::new().on_child_frame(&classify_child(line.as_bytes()), line.as_bytes()), ChildVerdict::Forward, "{line}");
        }
        let mut st = HostState::new();
        child(&mut st, &idle);
        assert_eq!(verdict(&st), Verdict::Idle, "idle on a fresh session");
        host(&mut st, USER);
        child(&mut st, &running);
        assert_eq!(verdict(&st), Verdict::Busy, "the turn's running: a turn at work");
        child(&mut st, &requires_action);
        child(&mut st, ASK);
        assert_eq!(verdict(&st), Verdict::Prompt, "requires_action, then the can_use_tool: a prompt");
        child(&mut st, &state("running", 3));
        assert_eq!(verdict(&st), Verdict::Prompt, "running with the ask still open: still a prompt");
        host(&mut st, r#"{"type":"control_response","response":{"subtype":"success","request_id":"perm-1","response":{"behavior":"allow"}}}"#);
        child(&mut st, RESULT);
        child(&mut st, &idle);
        assert_eq!(verdict(&st), Verdict::Idle, "answered, its result, then idle: idle");
    }

    /// S13 (A6-2, a control): a UserPromptSubmit hook's `hook_started` and `hook_response` frames (extension
    /// 2.1.312 sets `CLAUDE_CODE_EMIT_USER_PROMPT_SUBMIT_HOOK_EVENTS`, the wrapper forwards it) are forwarded
    /// unchanged and leave the verdict to the frames around them: on a fresh state idle; inside a turn busy until
    /// its result.
    #[test]
    fn prompt_hook_frames_never_change_the_verdict() {
        use crate::bridge::hoststate::ChildVerdict;
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let started = format!(r#"{{"type":"system","subtype":"hook_started","hook_id":"00000001-0000-4000-2200-000000000001","hook_name":"fake-hook","hook_event":"UserPromptSubmit","uuid":"00000001-0000-4000-2000-000000000001","session_id":"{sid}"}}"#);
        let response = format!(
            r#"{{"type":"system","subtype":"hook_response","hook_id":"00000001-0000-4000-2200-000000000001","hook_name":"fake-hook","hook_event":"UserPromptSubmit","output":"","stdout":"","stderr":"","exit_code":0,"outcome":"success","uuid":"00000001-0000-4000-2100-000000000001","session_id":"{sid}"}}"#
        );
        for line in [&started, &response] {
            assert_eq!(HostState::new().on_child_frame(&classify_child(line.as_bytes()), line.as_bytes()), ChildVerdict::Forward, "{line}");
        }
        let mut st = HostState::new();
        child(&mut st, &started);
        child(&mut st, &response);
        assert_eq!(verdict(&st), Verdict::Idle, "both on a fresh session: idle");
        let mut st = HostState::new();
        host(&mut st, USER);
        child(&mut st, &started);
        assert_eq!(verdict(&st), Verdict::Busy, "the turn's hook started: a turn at work");
        child(&mut st, &response);
        assert_eq!(verdict(&st), Verdict::Busy, "its response: still the turn");
        child(&mut st, RESULT);
        assert_eq!(verdict(&st), Verdict::Idle, "the result retired the line");
    }
}
