//! The S8 remote session (`[wrapper] mode = "remote"`): a stream-json session
//! under the roots runs in the workspace's MicroVM, behind the egress
//! allowlist, as the S2 pump's child on a remote link. Its pieces: [`link`]
//! (the pump's remote child and its adapter task; S8 wave 1, W1), and
//! [`pipeline`] (the pre-spawn steps P0–P4), [`env`] (the session's
//! environment) and [`prewarm`] (the `auth status` prewarm), all three S8
//! wave 1, W2.
//!
//! This module freezes what those builders share (S8 phase 0): the close and
//! grace budgets (C7), the census and audit names (C6), and what Cursor shows
//! when a remote session fails — an exit code and one `ai-env-claude:` line
//! naming the fix ([`Failure`], C5).
pub mod env;
pub mod link;
pub mod pipeline;
pub mod prewarm;

use crate::bridge::config::BridgeConfig;
use crate::bridge::errors::BridgeError;
use crate::bridge::pump::{INITIALIZE_WINDOW, INIT_FAIL_FAST};
use crate::bridge::remote::link::StartStep;
use crate::errors::CliError;
use crate::wire::frame::{DETACH_GRACE_SESSION_S, IDLE_DEFAULT_S, MAX_SPAWNS};
use crate::wire::redact::scrub;
use std::time::Duration;

// ---- C7: budgets ------------------------------------------------------------------------

/// Host EOF (or a signal) to the wrapper's exit: the whole remote close, v6
/// §2.8's CLOSE budget and the race suite's EOF bound.
pub const CLOSE_BUDGET_MS: u64 = 1500;
/// After host EOF (`stdin_eof` goes out at once): how long the CLI in the VM
/// has to exit by itself before the wrapper sends `detach{final}` and leaves
/// the rest to the shim's own ladder (L2). S7 measured that exit 0.5–1.1 s
/// after the CLI's stdin closed (B11: 1078 ms at the longest).
pub const REMOTE_EOF_DETACH_AFTER_MS: u64 = 1200;
/// After host EOF: the wrapper ends no matter what, as the local pump's
/// `EOF_HARD_STOP`, inside [`CLOSE_BUDGET_MS`].
pub const REMOTE_HARD_STOP_MS: u64 = 1400;
/// From the census start (T0) the pre-spawn steps P1–P4 must be done within
/// this: Cursor's initialize window less the fail-fast margin (`pump`'s
/// `INITIALIZE_WINDOW` and `INIT_FAIL_FAST`, v6 §2.8 "fail fast at T−10 s").
pub const INIT_DEADLINE: Duration = INITIALIZE_WINDOW.saturating_sub(INIT_FAIL_FAST);
/// What [`session_grace`] adds past the VM's idle suspend and the socket's idle bound.
pub const GRACE_MARGIN_S: u32 = 60;
/// `AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip` (debug builds only, L8): a resume's
/// generation 1 restores no transcript (S9: nothing pulled from S3, as S8's
/// upload sent nothing), so the resume miss, the seed retry (which always
/// restores) and the replay happen live (part B's dup probes). In
/// `REMOVED_ENV` and `LAB_UNSET`.
pub const TRANSCRIPT_KNOB: &str = "AI_ENV_BRIDGE_LAB_TRANSCRIPT";
/// `AI_ENV_BRIDGE_VM=<microvm id>` (plan §1): the remote wrapper's VM,
/// pinned (`Choice::Pin`), checked before any Touch ID ([`Failure::PinInvalid`],
/// [`Failure::PinGone`]). Honoured by release builds too, so not a lab knob
/// (not in the Makefile's `LAB_UNSET`); in `REMOVED_ENV` and the wrapper
/// tests' `WRAPPER_ENV`, so a pin in a developer's shell steers no test.
pub const PIN_KNOB: &str = "AI_ENV_BRIDGE_VM";

/// A remote session's `detach_grace_s` on a VM whose idle policy is
/// `vm_max_idle_s` (its row's: a VM keeps the policy it was started with, a
/// `vm run --idle` or an older config's; `None` when the row has none): how
/// long the shim keeps the spawn after its socket went, before TERM. At
/// least the S6 session default ([`DETACH_GRACE_SESSION_S`]), and past the
/// longer of that idle and `[vm].max_idle_s`, plus the socket's idle bound
/// ([`IDLE_DEFAULT_S`], which the wrapper sends in its `hello`) plus
/// [`GRACE_MARGIN_S`], so a VM that idled into suspend still holds the spawn
/// when the wrapper reattaches after the resume (plan §3 P4, §11; v6 L8(c)).
#[must_use]
pub fn session_grace(cfg: &BridgeConfig, vm_max_idle_s: Option<u32>) -> u32 {
    let idle = cfg.vm.max_idle_s.max(vm_max_idle_s.unwrap_or(0));
    DETACH_GRACE_SESSION_S.max(idle.saturating_add(IDLE_DEFAULT_S).saturating_add(GRACE_MARGIN_S))
}

// ---- C6: census and audit names (W1 and W2 write the values) -----------------------------

/// The parts a remote session adds to the census rows (`name:value`, joined
/// by `; `), after S2's (`end`, `child_pid`, …) and S7's `credential`; S2's
/// `init_ms` is measured from the census start (T0) for a remote session.
pub mod census_part {
    /// `vm:<microvm id>`.
    pub const VM: &str = "vm";
    /// `vm_how:<word>`, one of [`VM_HOW_WORDS`](super::VM_HOW_WORDS).
    pub const VM_HOW: &str = "vm_how";
    /// `spawn:<spawn id>`.
    pub const SPAWN: &str = "spawn";
    /// `vm_pid:<pid>`: the CLI's pid in the VM (Cursor sees the wrapper's own).
    pub const VM_PID: &str = "vm_pid";
    /// `claude:<version>`: the VM's claude.
    pub const CLAUDE: &str = "claude";
    /// `legs:<leg>=<ms>,…` over [`LEG_NAMES`](super::LEG_NAMES).
    pub const LEGS: &str = "legs";
    /// `seed:<word>`: what the workspace step did.
    pub const SEED: &str = "seed";
    /// `transcript:<word>`: the resume's transcript restore (S9:
    /// `workspace::TranscriptOutcome::word`: `restored`, `kept`, `staged`, `none`).
    pub const TRANSCRIPT: &str = "transcript";
    /// `fetch:<ok>/<n>`: the per-result code-out fetches.
    pub const FETCH: &str = "fetch";
    /// `close_ms:<ms>`: host EOF or the signal to the exit.
    pub const CLOSE_MS: &str = "close_ms";
    /// `link_drops:<n>`: sockets lost and reattached.
    pub const LINK_DROPS: &str = "link_drops";
    /// `auth_timers:match` or `auth_timers:unmeasured(<version>)`: the VM's
    /// claude against `authwatch::AUTH_TIMERS`.
    pub const AUTH_TIMERS: &str = "auth_timers";
    /// `pid_rewrite:ok` or `pid_rewrite:failed`: the `initialize` answer's pid.
    pub const PID_REWRITE: &str = "pid_rewrite";
    /// The start row's `prewarm:spawned(<pid>)` or `prewarm:skipped(<why>)`.
    pub const PREWARM: &str = "prewarm";
    /// Every part: the end row's, then the start row's.
    pub const ALL: [&str; 14] = [VM, VM_HOW, SPAWN, VM_PID, CLAUDE, LEGS, SEED, TRANSCRIPT, FETCH, CLOSE_MS, LINK_DROPS, AUTH_TIMERS, PID_REWRITE, PREWARM];
}

/// `vm_how`'s words: a VM the session started, one it reused running, one it
/// resumed, the one `AI_ENV_BRIDGE_VM` pins.
pub const VM_HOW_WORDS: [&str; 4] = ["started", "reused", "resumed", "pinned"];
/// The legs of `legs`, in order (each `<leg>=<ms>`); also the steps a
/// [`Failure::Deadline`] names.
pub const LEG_NAMES: [&str; 5] = ["touchid", "select", "workspace", "gate", "spawn"];
/// The `end:` words a remote session adds to `pump::EndReason`'s.
pub const END_WORDS: [&str; 2] = ["link_lost", "credential_rejected"];
/// The start row's mode notes: from `AI_ENV_BRIDGE_MODE`, from `[wrapper].mode`.
pub const MODE_NOTES: [&str; 2] = ["mode:remote", "mode:remote(config)"];

/// The audit events S8 adds (plan §12). The rows S4–S7 write already
/// (`vm_run`, `vm_reuse`, `credential_*`, `agent_*`, `endpoint_429`) carry a
/// purpose of [`PURPOSES`](super::PURPOSES) when a session or a prewarm writes them.
pub mod audit_event {
    /// The pipeline started its spawn: the VM, how it was chosen, each step's ms.
    pub const SESSION_REMOTE_START: &str = "session_remote_start";
    /// The session ended: the VM, the spawn, the exit, how it closed.
    pub const SESSION_REMOTE_END: &str = "session_remote_end";
    /// The session never started: the step, the exit, the [`Failure`](super::Failure)'s word.
    pub const SESSION_REMOTE_FAILED: &str = "session_remote_failed";
    /// SELECT_VM's choice.
    pub const VM_SELECT: &str = "vm_select";
    /// A seed, with its outcome word.
    pub const SEED: &str = "seed";
    /// A seed the scans or the VM refused.
    pub const SEED_REFUSED: &str = "seed_refused";
    /// A code-out fetch into `refs/remotes/box/*`.
    pub const CODEOUT_FETCH: &str = "codeout_fetch";
    /// A fetched ref that went to `refs/remotes/box-quarantine/*`.
    pub const BOX_FETCH_FINDING: &str = "box_fetch_finding";
    /// A settings capture into the quarantine.
    pub const SETTINGS_CAPTURE: &str = "settings_capture";
    /// `wrapper settings-sync --write`.
    pub const SETTINGS_SYNC: &str = "settings_sync";
    /// The `auth status` prewarm spawned its `vm warm`.
    pub const PREWARM: &str = "prewarm";
    /// The VM's claude is not the version `AUTH_TIMERS` measured (once per version).
    pub const AUTH_TIMERS_UNMEASURED: &str = "auth_timers_unmeasured";
    /// S9 (plans/s9-contracts.md §5.1): `box review`, the CLI's or the
    /// pre-push hook's: `repo`, `mode`, `remote` (a remote's name, else the
    /// literal `url`), `commits`, `findings`, `whole_history`, `verdict`, `ms`.
    pub const BOX_REVIEW: &str = "box_review";
    /// `box hook-install`: `repo`, `hook`, `outcome` (a dry run writes none).
    pub const HOOK_INSTALL: &str = "hook_install";
    /// `session drop-transport`: `session`, `wrapper_pid` (t8_6 chains it to the reconnects).
    pub const DROP_TRANSPORT: &str = "drop_transport";
    /// A transcript push to S3: `session`, `vm`, `kind`, `from`, `len`, `s3_status`, `version_id`, `ms`.
    pub const TRANSCRIPT_PUSH: &str = "transcript_push";
    /// A pull from S3 into the VM: `session`, `vm`, `parts`, `bytes`, `outcome`, `ms`.
    pub const TRANSCRIPT_PULL: &str = "transcript_pull";
    /// A view written on the Mac: `session`, `vm`, `messages`, `masked`, `bytes`, `outcome`.
    pub const TRANSCRIPT_VIEW: &str = "transcript_view";
    /// `session stage`: `session`, `bytes`, `parts`, `outcome`, `ms`.
    pub const TRANSCRIPT_STAGE: &str = "transcript_stage";
    /// `session gc --remote --yes`: `sessions`, `objects`, `older_than_days`.
    pub const TRANSCRIPT_GC: &str = "transcript_gc";
    /// `session migrate-s9`, per session: `session`, `from`, `outcome`, `bytes`.
    pub const TRANSCRIPT_MIGRATE: &str = "transcript_migrate";
    /// Every event above (never a URL, a query, a credential or a transcript byte in any detail).
    pub const ALL: [&str; 21] = [
        SESSION_REMOTE_START,
        SESSION_REMOTE_END,
        SESSION_REMOTE_FAILED,
        VM_SELECT,
        SEED,
        SEED_REFUSED,
        CODEOUT_FETCH,
        BOX_FETCH_FINDING,
        SETTINGS_CAPTURE,
        SETTINGS_SYNC,
        PREWARM,
        AUTH_TIMERS_UNMEASURED,
        BOX_REVIEW,
        HOOK_INSTALL,
        DROP_TRANSPORT,
        TRANSCRIPT_PUSH,
        TRANSCRIPT_PULL,
        TRANSCRIPT_VIEW,
        TRANSCRIPT_STAGE,
        TRANSCRIPT_GC,
        TRANSCRIPT_MIGRATE,
    ];
}

/// The `purpose` of the S4–S7 rows a remote session or a prewarm writes.
pub const PURPOSES: [&str; 2] = ["session", "prewarm"];

// ---- C5: what Cursor shows when a remote session fails ------------------------------------

/// The longest line a failure prints, its `ai-env-claude: ` prefix included.
pub const LINE_MAX: usize = 300;
/// The prefix the wrapper's voice prints [`Failure::line`] with.
const PREFIX: &str = "ai-env-claude: ";
/// The most of a quoted part (an error's first line) a line keeps, in characters.
const PART_MAX: usize = 160;
/// The most of a finding a line keeps, in characters: its fix after it is
/// the longest of the table, and stays whole.
const FINDING_MAX: usize = 150;
/// The most of a short part (a VM id, a code) a line keeps, in characters.
const SHORT_MAX: usize = 64;

/// Why a remote session failed, as Cursor shows it: the wrapper's exit code
/// ([`Failure::exit_code`]), then one `ai-env-claude:` line, the last of its
/// stderr ([`Failure::line`]), which names the fix, holds no secret (every
/// quoted part is scrubbed and cut) and fits [`LINE_MAX`] (plan §3's table).
/// P0 is before any AWS call or Touch ID, P1 the Touch ID, P2 SELECT_VM, P3
/// the workspace beside the gate and the token, P4 the spawn. An error no
/// kind was built for maps through [`Failure::from_error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// P0, exit 1: bridge.toml does not load, or fails a check the remote
    /// path makes (`first_line` of the error).
    Config { first_line: String },
    /// P0, exit 5: no sealed setup-token, or a seal Anthropic refused (`why`).
    NoToken { why: String },
    /// P0 or P1, exit 5: the runtime key is not sealed (absent, or a file
    /// that is no ai-env container: `why`), which `make runtime-key` seals.
    NoRuntimeKey { why: String },
    /// P0, exit 9: the workspace is not a git repository (D6).
    NotGitRepo,
    /// P0, exit 9: refused before any Touch ID: the provisional gate, a
    /// configured environment name, an unusable pinned VM (`what` names the
    /// name or the VM and the fix, never a value). P3's live gate, after the
    /// Touch ID, is [`Failure::GateRefused`].
    Refused { what: String },
    /// P0, exit 2: `AI_ENV_BRIDGE_VM` is not a MicroVM id.
    PinInvalid,
    /// P0, exit 8: the pinned VM has no row, or it was terminated.
    PinGone { vm: String },
    /// P1, or P3's token dialog, exit 3: the Touch ID dialog was dismissed.
    TouchIdCancelled,
    /// P1 or P3's token dialog, exit 5: no Touch ID within `secs`.
    TouchIdTimeout { secs: u64 },
    /// P2, exit 9: `running` VMs run already (`[vm].max_concurrent`; a
    /// closed chat's suspended VM counts, and `vm gc --yes` keeps every live
    /// one, so the line names `vm terminate`).
    MaxConcurrent { running: u32 },
    /// P2, exit `code` (7, 8 or 9; any other is taken as 7): SELECT_VM failed
    /// (an SDK error, a quota, not RUNNING in time, an egress mismatch).
    Select { code: i32, first_line: String },
    /// P3, exit 9: a tripwire or a settings widening in what the seed would
    /// carry (`finding`: the location, rule and key, never a value; its first
    /// line is shown, `workspace::code::FINDING`'s rule); at P1 or P3, a
    /// tripwire in what a `--resume`'s inline upload to S3 would send (a chat
    /// begun on this Mac, an S8 mirror: `transcript:REL`, a line of its own).
    Finding { finding: String },
    /// P0, exit 9 (S9): the chat's local transcript is over what a reopen
    /// carries inline (`wire::s3::INLINE_MAX`) and not staged: `ai-env
    /// session stage UUID --warm` sends it up first and restores it into the
    /// workspace's VM (R5-AWS-1: staged, it is still over what a reopen
    /// pulls inline); for an S8 remote chat's mirror (`s8_mirror`) `ai-env
    /// session migrate-s9` first, then the same `--warm` (once in S3 it is
    /// still over what a reopen pulls inline). Before any Touch ID.
    TranscriptTooLarge { session: String, bytes: u64, s8_mirror: bool },
    /// P0 or P3, exit 9 (S9, R5-AWS-1): the reopen would pull more of the
    /// chat's transcript from S3 than it pulls inline within Cursor's window
    /// (`wire::s3::INLINE_MAX` in all): `ai-env session stage UUID --warm`
    /// restores it into the workspace's VM first, where the reopen then
    /// keeps it. P0 refuses from local state alone, before any Touch ID; P3
    /// before any pull. `reuse_off`: `[vm].reuse_per_workspace` is off and
    /// no VM is pinned, so every reopen starts a new VM and `--warm` warms
    /// yet another: the line asks for the switch first.
    TranscriptPullTooLarge { session: String, bytes: u64, reuse_off: bool },
    /// P0 or P3, exit `code` (1, 7, 8 or 9; any other is taken as 1): the
    /// workspace step was refused or failed (`first_line` of the error):
    /// `resolve`'s unsupported repository or roots, the VM's refusal of the
    /// seed or the transcript, a git run, the data plane. A finding is
    /// [`Failure::Finding`], a workspace that is no git repository
    /// [`Failure::NotGitRepo`].
    Workspace { code: i32, first_line: String },
    /// P3, exit 9: the credential gate's live half refused the VM after the
    /// Touch ID (its egress, its image, the connector) (`first_line`, which
    /// says what to run).
    GateRefused { first_line: String },
    /// P2 to P4, exit 7: the VM's image predates the stage that added `cap`
    /// (`workspace_v1`: S8; S9's `transcript_s3_v1`, `git_http_v1`).
    OldImage { vm: String, cap: &'static str },
    /// P4, exit 9: the VM runs `limit` commands already.
    SpawnLimit { vm: String, limit: u32 },
    /// P4, exit 8: the VM's shim refused the hello (`code`).
    HelloRefused { code: String },
    /// Any step, exit `code` (5 at the Touch ID, else 7 or 8; any other is
    /// taken as 7): T0 + 50 s passed at `step`, one of [`LEG_NAMES`].
    Deadline { code: i32, step: &'static str },
    /// Pending, exit 143: a signal before the session started.
    Stopped,
    /// Running, exit 5: Anthropic refused the delivered setup-token (S7 D6).
    TokenRefused,
    /// Running, exit 8: the link stayed lost past its budget.
    LinkLost { vm: String },
    /// Any step, exit `code` (the error's own; 0 is taken as 1): an error no
    /// other kind names (`first_line`): a keystore key missing or not this
    /// Mac's (4), a corrupt file (6), a credential the runtime principal is
    /// refused (5), the shim refusing the command (`not_found`, `exec`,
    /// `cwd`), an I/O error. `step` is a `StartStep::name`.
    Other { code: i32, step: &'static str, first_line: String },
}

impl Failure {
    /// Every kind's [`Failure::word`].
    pub const WORDS: [&'static str; 24] = [
        "config",
        "no_token",
        "no_runtime_key",
        "not_git_repo",
        "refused",
        "pin_invalid",
        "pin_gone",
        "touchid_cancelled",
        "touchid_timeout",
        "max_concurrent",
        "select",
        "finding",
        "transcript_too_large",
        "transcript_pull_too_large",
        "workspace",
        "gate_refused",
        "old_image",
        "spawn_limit",
        "hello_refused",
        "deadline",
        "stopped",
        "token_refused",
        "link_lost",
        "other",
    ];

    /// The kind's stable word (the `why` of `session_remote_failed`).
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Failure::Config { .. } => "config",
            Failure::NoToken { .. } => "no_token",
            Failure::NoRuntimeKey { .. } => "no_runtime_key",
            Failure::NotGitRepo => "not_git_repo",
            Failure::Refused { .. } => "refused",
            Failure::PinInvalid => "pin_invalid",
            Failure::PinGone { .. } => "pin_gone",
            Failure::TouchIdCancelled => "touchid_cancelled",
            Failure::TouchIdTimeout { .. } => "touchid_timeout",
            Failure::MaxConcurrent { .. } => "max_concurrent",
            Failure::Select { .. } => "select",
            Failure::Finding { .. } => "finding",
            Failure::TranscriptTooLarge { .. } => "transcript_too_large",
            Failure::TranscriptPullTooLarge { .. } => "transcript_pull_too_large",
            Failure::Workspace { .. } => "workspace",
            Failure::GateRefused { .. } => "gate_refused",
            Failure::OldImage { .. } => "old_image",
            Failure::SpawnLimit { .. } => "spawn_limit",
            Failure::HelloRefused { .. } => "hello_refused",
            Failure::Deadline { .. } => "deadline",
            Failure::Stopped => "stopped",
            Failure::TokenRefused => "token_refused",
            Failure::LinkLost { .. } => "link_lost",
            Failure::Other { .. } => "other",
        }
    }

    /// The wrapper's exit code (Cursor shows it as `exited with code N`).
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Failure::Config { .. } => 1,
            Failure::PinInvalid => 2,
            Failure::TouchIdCancelled => 3,
            Failure::NoToken { .. } | Failure::NoRuntimeKey { .. } | Failure::TouchIdTimeout { .. } | Failure::TokenRefused => 5,
            Failure::OldImage { .. } => 7,
            Failure::PinGone { .. } | Failure::HelloRefused { .. } | Failure::LinkLost { .. } => 8,
            Failure::NotGitRepo | Failure::Refused { .. } | Failure::MaxConcurrent { .. } | Failure::Finding { .. } | Failure::TranscriptTooLarge { .. } | Failure::TranscriptPullTooLarge { .. } | Failure::GateRefused { .. } | Failure::SpawnLimit { .. } => 9,
            Failure::Select { code, .. } if matches!(code, 7..=9) => *code,
            Failure::Deadline { code, .. } if matches!(code, 5 | 7 | 8) => *code,
            Failure::Select { .. } | Failure::Deadline { .. } => 7,
            Failure::Workspace { code, .. } if matches!(code, 1 | 7..=9) => *code,
            Failure::Workspace { .. } => 1,
            Failure::Other { code: 0, .. } => 1,
            Failure::Other { code, .. } => *code,
            Failure::Stopped => 143,
        }
    }

    /// The failure an error at `step` is: the one mapping W1's adapter (a
    /// spawn refused before `spawned`) and W2's pipeline (P0 to P4) share. By
    /// the error first: a dismissed Touch ID (P1, or the token's at P3),
    /// `[vm].max_concurrent`, a scan finding (a tripwire, a settings widening,
    /// `workspace::code::FINDING`), a workspace that is no git repository
    /// (`workspace::code::NOT_A_GIT_REPO`), a VM without `workspace_v1`, a
    /// transcript over what a reopen carries or pulls inline (S9), the
    /// shim's spawn limit, a refused hello. Then by the step: P0's bridge.toml
    /// check is `Config`; a workspace refusal or failure at P0, or any error
    /// of exit 1, 7, 8 or 9 at P3's workspace step, `Workspace`; another P0
    /// refusal (exit 9) `Refused`; a P2 error of exit 7 to 9 `Select`; a
    /// refusal at P3's gate `GateRefused`. Anything else is `Other`, with the
    /// error's own exit code. W2 builds `NoToken`, `NoRuntimeKey`,
    /// `PinInvalid`, `PinGone`, `TouchIdTimeout`, `Deadline` and `Stopped`
    /// itself, from what it knows; W1 builds the running ones. `vm`: the VM,
    /// once SELECT_VM chose one. By value: the exit code is `CliError::from`'s.
    #[must_use]
    pub fn from_error(step: StartStep, e: BridgeError, vm: Option<&str>) -> Failure {
        use crate::bridge::workspace::code as ws;
        let vm = || vm.unwrap_or("the VM").to_string();
        match &e {
            BridgeError::Cancelled | BridgeError::Cli(CliError::Cancelled) => return Failure::TouchIdCancelled,
            BridgeError::MaxConcurrent(running) => return Failure::MaxConcurrent { running: *running },
            BridgeError::Tripwire(m) | BridgeError::SettingsWidening(m) | BridgeError::WorkspaceRefused { code: ws::FINDING, message: m } => return Failure::Finding { finding: m.clone() },
            BridgeError::WorkspaceRefused { code: ws::NOT_A_GIT_REPO, .. } => return Failure::NotGitRepo,
            BridgeError::NoCapability { cap, .. } => return Failure::OldImage { vm: vm(), cap },
            BridgeError::TranscriptTooLarge { session, bytes } => return Failure::TranscriptTooLarge { session: session.clone(), bytes: *bytes, s8_mirror: false },
            BridgeError::TranscriptPullTooLarge { session, bytes } => return Failure::TranscriptPullTooLarge { session: session.clone(), bytes: *bytes, reuse_off: false },
            BridgeError::SpawnRefused { code: "limit", .. } => return Failure::SpawnLimit { vm: vm(), limit: MAX_SPAWNS as u32 },
            BridgeError::HelloRefused { code, .. } => return Failure::HelloRefused { code: code.clone() },
            _ => {}
        }
        let config = matches!(e, BridgeError::Config(_));
        let workspace = matches!(e, BridgeError::WorkspaceRefused { .. } | BridgeError::WorkspaceFailed { .. } | BridgeError::OutsideRoots(_));
        let first_line = e.to_string();
        let code = CliError::from(e).exit_code();
        match step {
            StartStep::Precheck if config => Failure::Config { first_line },
            StartStep::Precheck if workspace => Failure::Workspace { code, first_line },
            StartStep::Workspace if workspace || matches!(code, 1 | 7..=9) => Failure::Workspace { code, first_line },
            StartStep::Precheck if code == 9 => Failure::Refused { what: first_line },
            StartStep::SelectVm if matches!(code, 7..=9) => Failure::Select { code, first_line },
            StartStep::Gate if code == 9 => Failure::GateRefused { first_line },
            _ => Failure::Other { code, step: step.name(), first_line },
        }
    }

    /// The text after `ai-env-claude: `: what failed and the fix, on one line
    /// of at most [`LINE_MAX`] characters with the prefix.
    #[must_use]
    pub fn line(&self) -> String {
        let text = match self {
            Failure::Config { first_line } => format!("{}; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally", part(first_line, PART_MAX)),
            Failure::NoToken { why } => format!("{}: run ai-env creds setup-token", part(why, PART_MAX)),
            Failure::NoRuntimeKey { why } => format!("{}: run make runtime-key", part(why, PART_MAX)),
            Failure::NotGitRepo => "not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally".to_string(),
            Failure::Refused { what } => format!("refused before any Touch ID: {}", part(what, PART_MAX)),
            Failure::PinInvalid => format!("{PIN_KNOB} is not a MicroVM id: unset it, or name a VM ai-env vm list shows"),
            Failure::PinGone { vm } => format!("the pinned VM {} ({PIN_KNOB}) is gone or has no row: unset {PIN_KNOB}, or pin a VM ai-env vm list shows", part(vm, SHORT_MAX)),
            Failure::TouchIdCancelled => "Touch ID was cancelled: nothing was started; reopen the chat to try again".to_string(),
            Failure::TouchIdTimeout { secs } => format!("no Touch ID within {secs} s (Cursor's 60 s window): nothing was started; ai-env vm warm prepares the VM ahead"),
            Failure::MaxConcurrent { running: 1 } => "1 VM already runs ([vm].max_concurrent, suspended ones included): ai-env vm list names them; ai-env vm terminate ID frees a slot, then reopen the chat".to_string(),
            Failure::MaxConcurrent { running } => format!("{running} VMs already run ([vm].max_concurrent, suspended ones included): ai-env vm list names them; ai-env vm terminate ID frees a slot, then reopen the chat"),
            Failure::Select { first_line, .. } => format!("{}; ai-env doctor checks the setup", part(first_line, PART_MAX)),
            Failure::Finding { finding } if finding.starts_with("transcript:") => format!("the chat's transcript would carry {}: none of it was sent; AI_ENV_BRIDGE_LOCAL=1 reopens the chat on this Mac, or start a new one", part(finding, FINDING_MAX)),
            // `box seed` lists an update's findings too (its history: after its Touch ID); the dry run plans a first seed only.
            Failure::Finding { finding } => format!("the seed would carry {}: remove or ignore it (repo settings: trust_repo_settings); ai-env box seed lists the findings", part(finding, FINDING_MAX)),
            Failure::TranscriptTooLarge { session, bytes, s8_mirror } => {
                let size = crate::bridge::workspace::snapshot::human_bytes(*bytes);
                let inline = crate::wire::s3::INLINE_MAX >> 20;
                if *s8_mirror {
                    // Migrated, it is a chat S3 holds over what a reopen pulls inline: `--warm` after it.
                    format!("the chat's transcript is {size} (over the {inline} MiB a reopen carries inline): run ai-env session migrate-s9 --yes, then ai-env session stage {} --warm, in a terminal, then reopen the chat", part(session, SHORT_MAX))
                } else {
                    // `--warm` too (R5-AWS-1): once staged, a chat over the cap reopens only from a VM that holds it.
                    format!("the chat's transcript is {size} (over the {inline} MiB a reopen carries inline): run ai-env session stage {} --warm in a terminal, then reopen the chat", part(session, SHORT_MAX))
                }
            }
            Failure::TranscriptPullTooLarge { session, bytes, reuse_off } => {
                // With reuse off a reopen never takes the VM `--warm` warmed: the switch first.
                let reuse = if *reuse_off { ", and [vm] reuse_per_workspace is off: set it to true," } else { ":" };
                format!(
                    "the chat's transcript in S3 is {}, over the {} MiB a reopen pulls inline{reuse} run ai-env session stage {} --warm in a terminal, then reopen the chat",
                    crate::bridge::workspace::snapshot::human_bytes(*bytes),
                    crate::wire::s3::INLINE_MAX >> 20,
                    part(session, SHORT_MAX)
                )
            }
            Failure::Workspace { first_line, .. } => {
                // A refusal names its own remedy (the VM's, say): it keeps the room the line has.
                let fix = "; ai-env box seed --dry-run shows the plan";
                format!("{}{fix}", part(first_line, LINE_MAX - PREFIX.len() - fix.len()))
            }
            Failure::GateRefused { first_line } => format!("{}; ai-env doctor checks the credential gate", part(first_line, PART_MAX)),
            Failure::OldImage { vm, cap } => format!("{} runs an image older than {} (no {cap}): run make deploy, then reopen the chat", part(vm, SHORT_MAX), crate::wire::frame::cap_stage(cap)),
            Failure::SpawnLimit { vm, limit } => {
                let vm = part(vm, SHORT_MAX);
                format!("{vm} runs {limit} commands already: close a chat, or ai-env vm health {vm} --detail")
            }
            Failure::HelloRefused { code } => format!("the VM refused the session ({}): ai-env vm list, ai-env vm terminate it, then reopen the chat", part(code, SHORT_MAX)),
            Failure::Deadline { step, .. } => format!("did not start within Cursor's 60 s window (stuck at {}): ai-env vm warm prepares the VM ahead", part(step, SHORT_MAX)),
            Failure::Stopped => "stopped before the session started: nothing was started; reopen the chat to start it".to_string(),
            Failure::TokenRefused => "Anthropic refused the delivered setup-token (HTTP 401): the session was stopped and is not started again; seal a fresh one with `claude setup-token`, then `ai-env creds setup-token`".to_string(),
            Failure::LinkLost { vm } => format!("lost the VM {}: reopen the chat from the picker", part(vm, SHORT_MAX)),
            Failure::Other { step, first_line, .. } => format!("{} (at {step}); ai-env doctor checks the setup; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally", part(first_line, PART_MAX)),
        };
        cut(&text, LINE_MAX - PREFIX.len())
    }
}

/// The first line of `text`, scrubbed, control characters blanked, at most
/// `max` characters.
fn part(text: &str, max: usize) -> String {
    let first = text.lines().next().unwrap_or_default();
    let shown: String = scrub(first).chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    cut(&shown, max)
}

/// `text` cut to `max` characters, an ellipsis last when anything was cut.
fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v6 §2.8: CLOSE within 1.5 s of host EOF, the race suite's bound.
    #[test]
    fn close_budget_is_v6s_one_and_a_half_seconds() {
        assert_eq!(CLOSE_BUDGET_MS, 1500);
    }

    /// L2: the CLI's own exit (S7: 0.5–1.1 s after stdin closed, B11's
    /// longest 1078 ms) fits before `detach{final}`, and the hard stop is the
    /// local pump's, both inside the close budget.
    #[test]
    fn the_remote_eof_rungs_leave_the_clis_own_exit_room() {
        assert_eq!(REMOTE_EOF_DETACH_AFTER_MS, 1200);
        const { assert!(REMOTE_EOF_DETACH_AFTER_MS > 1078, "S7 B11's slowest exit fits") };
        assert_eq!(u128::from(REMOTE_HARD_STOP_MS), crate::bridge::pump::EOF_HARD_STOP.as_millis(), "the local hard stop");
        const { assert!(REMOTE_EOF_DETACH_AFTER_MS < REMOTE_HARD_STOP_MS && REMOTE_HARD_STOP_MS < CLOSE_BUDGET_MS) };
    }

    /// v6 §2.8: fail fast at T−10 s of Cursor's 60 s window, so the pipeline's deadline is T0 + 50 s.
    #[test]
    fn the_init_deadline_is_t0_plus_fifty_seconds() {
        assert_eq!(INIT_DEADLINE, Duration::from_secs(50));
    }

    /// Plan §3 P4 and §11: max(900, max_idle_s + 90 + 60), the idle the VM's
    /// own (its row's) when it is the longer: a reused VM keeps the policy it
    /// was started with (v6 L8(c)).
    #[test]
    fn the_session_grace_covers_max_idle() {
        let with_idle = |s: u32, vm: Option<u32>| {
            let mut cfg = BridgeConfig::default();
            cfg.vm.max_idle_s = s;
            session_grace(&cfg, vm)
        };
        assert_eq!(session_grace(&BridgeConfig::default(), None), 900, "the default idle (300 s) stays under the S6 floor");
        assert_eq!(with_idle(750, None), 900);
        assert_eq!(with_idle(751, None), 901);
        assert_eq!(with_idle(28_800, None), 28_950, "the longest idle the config allows");
        assert_eq!(with_idle(300, Some(3600)), 3750, "a VM started with vm run --idle 3600");
        assert_eq!(with_idle(1200, Some(300)), 1350, "never under the config's");
        assert_eq!(with_idle(300, Some(300)), 900);
        assert_eq!((DETACH_GRACE_SESSION_S, IDLE_DEFAULT_S, GRACE_MARGIN_S), (900, 90, 60));
    }

    /// The knob's name, as `REMOVED_ENV` and the Makefile's `LAB_UNSET` hold it.
    #[test]
    fn the_transcript_knob_is_a_lab_knob() {
        assert_eq!(TRANSCRIPT_KNOB, "AI_ENV_BRIDGE_LAB_TRANSCRIPT");
    }

    /// The pin's name, as `REMOVED_ENV` and `WRAPPER_ENV` hold it, and as its
    /// two failures name it; a release knob, so no lab knob's name.
    #[test]
    fn the_pin_knob_is_the_one_its_failures_name() {
        assert_eq!(PIN_KNOB, "AI_ENV_BRIDGE_VM");
        assert!(!PIN_KNOB.starts_with("AI_ENV_BRIDGE_LAB_"));
        assert!(Failure::PinInvalid.line().starts_with(&format!("{PIN_KNOB} is not a MicroVM id")));
        assert!(Failure::PinGone { vm: "microvm-1".into() }.line().contains(&format!("unset {PIN_KNOB}")));
    }

    fn snake(name: &str) -> bool {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }

    /// C6: every name is new, unique and snake_case; none is a part, an end
    /// word or an event S2–S7 already write.
    #[test]
    fn the_census_and_audit_names_are_unique_and_new() {
        let s2_parts = ["end", "child_pid", "respawns", "mirror", "dropped", "oauth_refresh_answered", "init_ms", "eof_to_sigterm_ms", "credential", "synthetic_oauth", "mode", "mode_invalid", "lab_exit", "local_fallback"];
        let parts: std::collections::BTreeSet<&str> = census_part::ALL.iter().copied().collect();
        assert_eq!(parts.len(), census_part::ALL.len(), "unique census parts");
        for p in census_part::ALL {
            assert!(snake(p) && !s2_parts.contains(&p), "{p}");
        }
        use crate::bridge::pump::EndReason;
        let ends = [EndReason::ChildExit, EndReason::EofTerm, EndReason::EofKill, EndReason::SigTerm, EndReason::HostGone, EndReason::LabExit, EndReason::SpawnFailed].map(EndReason::name);
        for w in END_WORDS {
            assert!(snake(w) && !ends.contains(&w), "{w}");
        }
        assert_eq!([EndReason::LinkLost, EndReason::CredentialRejected].map(EndReason::name), END_WORDS, "the reasons the pump gained (C3)");
        let earlier = [
            // S8's resume upload, gone at S9's S3 cut-over: its name is never written again.
            "transcript_put",
            "resume_seed_retry",
            "resume_seed_miss",
            "resume_seed_failed",
            "replay_timeout",
            "oauth_refresh_answered",
            "synthetic_oauth",
            "lab_probe",
            "vm_run",
            "vm_reuse",
            "vm_adopt",
            "vm_suspend",
            "vm_terminate",
            "vm_token",
            "vm_egress_internet",
            "credential_unseal",
            "credential_gate",
            "credential_deliver",
            "credential_rejected",
            "agent_reconnect",
            "agent_remint",
            "agent_rotate",
            "endpoint_429",
            "egress_check",
            "egress_reload",
            "infra_status_write",
            "creds_combined",
        ];
        let events: std::collections::BTreeSet<&str> = audit_event::ALL.iter().copied().collect();
        assert_eq!(events.len(), audit_event::ALL.len(), "unique audit events");
        for e in audit_event::ALL {
            assert!(snake(e) && !earlier.contains(&e), "{e}");
        }
        for w in VM_HOW_WORDS.iter().chain(LEG_NAMES.iter()).chain(PURPOSES.iter()) {
            assert!(snake(w), "{w}");
        }
        assert!(MODE_NOTES.iter().all(|n| n.starts_with("mode:remote")));
    }

    /// The fix a kind's line names (exhaustive: a new kind fails to compile here until its row is added).
    fn fix_of(f: &Failure) -> &'static str {
        match f {
            Failure::Config { .. } | Failure::NotGitRepo => "AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally",
            Failure::NoToken { .. } => "run ai-env creds setup-token",
            Failure::NoRuntimeKey { .. } => "run make runtime-key",
            Failure::Refused { .. } => "refused before any Touch ID: ",
            Failure::PinInvalid | Failure::PinGone { .. } => "ai-env vm list",
            Failure::TouchIdCancelled => "reopen the chat",
            Failure::TouchIdTimeout { .. } | Failure::Deadline { .. } => "ai-env vm warm prepares the VM ahead",
            Failure::MaxConcurrent { .. } => "ai-env vm terminate ID frees a slot",
            Failure::Select { .. } => "ai-env doctor",
            Failure::Finding { finding } if finding.starts_with("transcript:") => "AI_ENV_BRIDGE_LOCAL=1 reopens the chat",
            Failure::Finding { .. } => "ai-env box seed lists the findings",
            Failure::TranscriptTooLarge { s8_mirror: true, .. } => "run ai-env session migrate-s9 --yes, then ai-env session stage",
            Failure::TranscriptTooLarge { .. } => "ai-env session stage",
            Failure::TranscriptPullTooLarge { reuse_off: true, .. } => "[vm] reuse_per_workspace is off: set it to true, run ai-env session stage",
            Failure::TranscriptPullTooLarge { .. } => "--warm in a terminal, then reopen the chat",
            Failure::Workspace { .. } => "ai-env box seed --dry-run shows the plan",
            Failure::GateRefused { .. } => "ai-env doctor checks the credential gate",
            Failure::OldImage { .. } => "make deploy",
            Failure::SpawnLimit { .. } => "--detail",
            Failure::HelloRefused { .. } => "ai-env vm terminate",
            Failure::Stopped => "reopen the chat",
            Failure::TokenRefused => "ai-env creds setup-token",
            Failure::LinkLost { .. } => "reopen the chat from the picker",
            Failure::Other { .. } => "ai-env doctor checks the setup",
        }
    }

    /// C5, over every kind: its exit code (plan §3's table), its fix, one line
    /// of at most 300 characters with the prefix, and no secret even when a
    /// quoted part holds one (a long first line, a token, an access key id).
    #[test]
    fn every_failure_names_its_fix_in_one_short_secret_free_line() {
        let token = format!("{}-{}-{}-{}", "sk", "ant", "oat01", "c".repeat(60));
        let key_id = format!("{}{}", "AKIA", "Z".repeat(16));
        let long = format!("aws run_microvm: {} holds {token} and {key_id}\nsecond line", "x".repeat(400));
        let vm = format!("microvm-{}", "f".repeat(100));
        let cases: Vec<(Failure, i32)> = vec![
            (Failure::Config { first_line: long.clone() }, 1),
            (Failure::NoToken { why: format!("the sealed setup-token {token} was refused") }, 5),
            (Failure::NoRuntimeKey { why: "/Users/mike/.config/ai-env/bridge/credentials/aws.env does not exist".into() }, 5),
            (Failure::NotGitRepo, 9),
            (Failure::Refused { what: long.clone() }, 9),
            (Failure::PinInvalid, 2),
            (Failure::PinGone { vm: vm.clone() }, 8),
            (Failure::TouchIdCancelled, 3),
            (Failure::TouchIdTimeout { secs: 47 }, 5),
            (Failure::MaxConcurrent { running: 3 }, 9),
            (Failure::MaxConcurrent { running: 1 }, 9),
            (Failure::Select { code: 7, first_line: long.clone() }, 7),
            (Failure::Select { code: 8, first_line: "microvm not found: microvm-x".into() }, 8),
            (Failure::Select { code: 9, first_line: "egress mismatch".into() }, 9),
            (Failure::Select { code: 1, first_line: "busy".into() }, 7),
            (Failure::Finding { finding: format!("refs/heads/dev:cfg/prod.yaml line 3 rule aws-key {key_id}") }, 9),
            (Failure::Finding { finding: "transcript:0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl line 2: rule aws-access-key-id".into() }, 9),
            (Failure::TranscriptTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 1_870_000_000, s8_mirror: false }, 9),
            (Failure::TranscriptTooLarge { session: format!("{token}{}", "s".repeat(300)), bytes: 70 << 20, s8_mirror: true }, 9),
            (Failure::TranscriptPullTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 1 << 30, reuse_off: false }, 9),
            (Failure::TranscriptPullTooLarge { session: format!("{token}{}", "s".repeat(300)), bytes: 70 << 20, reuse_off: false }, 9),
            (Failure::TranscriptPullTooLarge { session: format!("{token}{}", "s".repeat(300)), bytes: u64::MAX, reuse_off: true }, 9),
            (Failure::Workspace { code: 9, first_line: format!("workspace refused (symlink_component): PUT /seed: {token}") }, 9),
            (Failure::Workspace { code: 1, first_line: long.clone() }, 1),
            (Failure::Workspace { code: 8, first_line: "microvm terminated: gone".into() }, 8),
            (Failure::Workspace { code: 5, first_line: "credentials unavailable".into() }, 1),
            (Failure::GateRefused { first_line: long.clone() }, 9),
            (Failure::OldImage { vm: vm.clone(), cap: crate::wire::frame::CAP_WORKSPACE_V1 }, 7),
            (Failure::OldImage { vm: vm.clone(), cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1 }, 7),
            (Failure::SpawnLimit { vm: vm.clone(), limit: 8 }, 9),
            (Failure::HelloRefused { code: format!("bad_token {token}") }, 8),
            (Failure::Deadline { code: 5, step: "touchid" }, 5),
            (Failure::Deadline { code: 8, step: "spawn" }, 8),
            (Failure::Deadline { code: 3, step: "select" }, 7),
            (Failure::Stopped, 143),
            (Failure::TokenRefused, 5),
            (Failure::LinkLost { vm: vm.clone() }, 8),
            (Failure::Other { code: 4, step: "touchid", first_line: long.clone() }, 4),
            (Failure::Other { code: 6, step: "touchid", first_line: format!("corrupt: {key_id}") }, 6),
            (Failure::Other { code: 0, step: "spawn", first_line: "broken pipe".into() }, 1),
        ];
        let covered: std::collections::BTreeSet<&str> = cases.iter().map(|(f, _)| f.word()).collect();
        let words: std::collections::BTreeSet<&str> = Failure::WORDS.iter().copied().collect();
        assert_eq!(covered, words, "one case per kind at least");
        assert_eq!(words.len(), Failure::WORDS.len(), "unique words");
        for (f, code) in &cases {
            let printed = format!("{PREFIX}{}", f.line());
            assert_eq!(f.exit_code(), *code, "{f:?}");
            assert!(printed.chars().count() <= LINE_MAX, "{} chars: {printed}", printed.chars().count());
            assert!(!printed.contains('\n') && !printed.contains("second line"), "one line: {printed}");
            assert!(!printed.contains(&token) && !printed.contains(&key_id), "no secret: {printed}");
            assert!(printed.contains(fix_of(f)), "{} names its fix ({}): {printed}", f.word(), fix_of(f));
        }
        // A quoted part keeps its start, cut with an ellipsis, and the fix after it survives.
        let config = Failure::Config { first_line: long }.line();
        assert!(config.starts_with("aws run_microvm: xxx") && config.contains("\u{2026}; AI_ENV_BRIDGE_LOCAL=1"), "{config}");
        assert_eq!(Failure::NotGitRepo.line(), "not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally", "plan §1's text");
        // S9: the old image names the stage its cap needs (workspace_v1's text unchanged); one VM is singular (F5).
        assert_eq!(Failure::OldImage { vm: "microvm-1".into(), cap: crate::wire::frame::CAP_WORKSPACE_V1 }.line(), "microvm-1 runs an image older than S8 (no workspace_v1): run make deploy, then reopen the chat");
        assert_eq!(Failure::OldImage { vm: "microvm-1".into(), cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1 }.line(), "microvm-1 runs an image older than S9 (no transcript_s3_v1): run make deploy, then reopen the chat");
        assert!(Failure::MaxConcurrent { running: 1 }.line().starts_with("1 VM already runs ("));
        assert!(Failure::MaxConcurrent { running: 2 }.line().starts_with("2 VMs already run ("));
        let big = Failure::TranscriptTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 70 << 20, s8_mirror: false };
        assert_eq!(big.line(), "the chat's transcript is 70.0 MiB (over the 64 MiB a reopen carries inline): run ai-env session stage 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b --warm in a terminal, then reopen the chat");
        let mirror = Failure::TranscriptTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 70 << 20, s8_mirror: true };
        // Migrated, a mirror over the cap is a chat S3 holds over what a reopen pulls inline: --warm after it.
        assert!(mirror.line().ends_with("inline): run ai-env session migrate-s9 --yes, then ai-env session stage 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b --warm, in a terminal, then reopen the chat"), "{}", mirror.line());
        // R5-AWS-1: a chat S3 holds, over what a reopen pulls within Cursor's window, names the --warm restore.
        let pull = Failure::TranscriptPullTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 70 << 20, reuse_off: false };
        assert_eq!(pull.line(), "the chat's transcript in S3 is 70.0 MiB, over the 64 MiB a reopen pulls inline: run ai-env session stage 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b --warm in a terminal, then reopen the chat");
        // With reuse off every reopen starts a new VM, and --warm warms yet another: the switch first.
        let off = Failure::TranscriptPullTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 70 << 20, reuse_off: true };
        assert_eq!(off.line(), "the chat's transcript in S3 is 70.0 MiB, over the 64 MiB a reopen pulls inline, and [vm] reuse_per_workspace is off: set it to true, run ai-env session stage 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b --warm in a terminal, then reopen the chat");
    }

    /// Every quoted part at its longest still leaves the fix after it whole:
    /// a line is cut inside its parts only, never in its trailer.
    #[test]
    fn a_longest_part_never_cuts_the_fix_after_it() {
        let long = "y".repeat(400);
        let mut cases: Vec<(Failure, &str)> = vec![
            (Failure::Config { first_line: long.clone() }, "; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally"),
            (Failure::NoToken { why: long.clone() }, ": run ai-env creds setup-token"),
            (Failure::NoRuntimeKey { why: long.clone() }, ": run make runtime-key"),
            (Failure::PinGone { vm: long.clone() }, "or pin a VM ai-env vm list shows"),
            (Failure::Select { code: 7, first_line: long.clone() }, "; ai-env doctor checks the setup"),
            (Failure::Finding { finding: long.clone() }, "; ai-env box seed lists the findings"),
            (Failure::Finding { finding: format!("transcript:{long}") }, ": none of it was sent; AI_ENV_BRIDGE_LOCAL=1 reopens the chat on this Mac, or start a new one"),
            (Failure::Workspace { code: 9, first_line: long.clone() }, "; ai-env box seed --dry-run shows the plan"),
            (Failure::GateRefused { first_line: long.clone() }, "; ai-env doctor checks the credential gate"),
            (Failure::OldImage { vm: long.clone(), cap: crate::wire::frame::CAP_GIT_HTTP_V1 }, "run make deploy, then reopen the chat"),
            (Failure::TranscriptTooLarge { session: long.clone(), bytes: u64::MAX, s8_mirror: false }, "in a terminal, then reopen the chat"),
            (Failure::TranscriptTooLarge { session: long.clone(), bytes: u64::MAX, s8_mirror: true }, " --warm, in a terminal, then reopen the chat"),
            (Failure::TranscriptPullTooLarge { session: long.clone(), bytes: u64::MAX, reuse_off: false }, " --warm in a terminal, then reopen the chat"),
            (Failure::TranscriptPullTooLarge { session: long.clone(), bytes: u64::MAX, reuse_off: true }, " --warm in a terminal, then reopen the chat"),
            (Failure::SpawnLimit { vm: long.clone(), limit: 8 }, " --detail"),
            (Failure::HelloRefused { code: long.clone() }, "ai-env vm terminate it, then reopen the chat"),
            (Failure::LinkLost { vm: long.clone() }, ": reopen the chat from the picker"),
        ];
        for step in StartStep::ALL {
            cases.push((Failure::Other { code: 1, step: step.name(), first_line: long.clone() }, "; ai-env doctor checks the setup; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally"));
            cases.push((Failure::Deadline { code: 7, step: step.name() }, ": ai-env vm warm prepares the VM ahead"));
        }
        for (f, trailer) in cases {
            let line = f.line();
            assert!(line.ends_with(trailer), "{}: {line}", f.word());
            assert!(format!("{PREFIX}{line}").chars().count() <= LINE_MAX, "{}: {line}", f.word());
        }
        let finding = Failure::Finding { finding: long }.line();
        assert!(finding.starts_with(&format!("the seed would carry {}\u{2026}:", "y".repeat(FINDING_MAX - 1))), "{finding}");
    }

    /// One mapping from an error to what Cursor shows: by the error where it
    /// says what happened, else by the step; the exit code is the error's
    /// own unless a kind fixes it. Every line still passes C5's rules.
    #[test]
    fn errors_map_to_their_failure_by_error_then_by_step() {
        use crate::bridge::workspace::code as ws;
        use crate::wire::workspace::refusal;
        use StartStep::*;
        let token = format!("{}-{}-{}-{}", "sk", "ant", "oat01", "e".repeat(60));
        let vm = Some("microvm-1");
        let cases: Vec<(StartStep, BridgeError, &str, i32)> = vec![
            (TouchId, BridgeError::Cli(CliError::Cancelled), "touchid_cancelled", 3),
            (Token, BridgeError::Cancelled, "touchid_cancelled", 3),
            (SelectVm, BridgeError::MaxConcurrent(3), "max_concurrent", 9),
            (Workspace, BridgeError::Tripwire("refs/heads/dev:cfg/a.yaml line 3: rule aws-key".into()), "finding", 9),
            (Workspace, BridgeError::WorkspaceRefused { code: ws::FINDING, message: "untracked .env: rule env-file-plaintext".into() }, "finding", 9),
            (Precheck, BridgeError::WorkspaceRefused { code: ws::NOT_A_GIT_REPO, message: "/Users/mike/notes".into() }, "not_git_repo", 9),
            (Precheck, BridgeError::WorkspaceFailed { code: ws::UNSUPPORTED_REPO, message: "a shallow repository".into() }, "workspace", 1),
            (Precheck, BridgeError::WorkspaceRefused { code: ws::OUTSIDE_ROOTS, message: "/Users/mike/x".into() }, "workspace", 9),
            (Precheck, BridgeError::Config("[vm].max_idle_s: 0".into()), "config", 1),
            (Precheck, BridgeError::Policy(format!("[wrapper].env_extra names {token}")), "refused", 9),
            (Precheck, BridgeError::Cli(CliError::AuthUnavailable("no setup-token is sealed".into())), "other", 5),
            (TouchId, BridgeError::Cli(CliError::NoKey("keystore key ai-env absent".into())), "other", 4),
            (TouchId, BridgeError::Cli(CliError::Corrupt("aws.env".into())), "other", 6),
            (SelectVm, BridgeError::Sdk { op: "run_microvm", message: "InsufficientCapacityException".into() }, "select", 7),
            (SelectVm, BridgeError::VmNotFound("microvm-1".into()), "select", 8),
            (SelectVm, BridgeError::egress_mismatch("microvm-1", vec![], vec![], true), "select", 9),
            (SelectVm, BridgeError::Busy("workspace busy (pid 1)".into()), "other", 1),
            (SelectVm, BridgeError::CredentialsUnavailable("run_microvm: UnrecognizedClientException".into()), "other", 5),
            (Workspace, BridgeError::WorkspaceRefused { code: refusal::SYMLINK_COMPONENT, message: "PUT /seed: a component is a symlink".into() }, "workspace", 9),
            (Workspace, BridgeError::WorkspaceFailed { code: refusal::GIT_FAILED, message: "PUT /seed: git exited 128".into() }, "workspace", 1),
            (Workspace, BridgeError::Terminated("PUT /seed: gone".into()), "workspace", 8),
            (Workspace, BridgeError::Endpoint("connect refused".into()), "workspace", 7),
            (Workspace, BridgeError::CredentialsUnavailable("mint: expired".into()), "other", 5),
            (Workspace, BridgeError::NoCapability { cap: "workspace_v1", message: "GET /seed answered 404".into() }, "old_image", 7),
            (SelectVm, BridgeError::NoCapability { cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1, message: "microvm-1 names no transcript_s3_v1".into() }, "old_image", 7),
            (Precheck, BridgeError::TranscriptTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 70 << 20 }, "transcript_too_large", 9),
            (Workspace, BridgeError::TranscriptPullTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 70 << 20 }, "transcript_pull_too_large", 9),
            (Gate, BridgeError::Policy("no credential for microvm-1: run ai-env egress check".into()), "gate_refused", 9),
            (Gate, BridgeError::Sdk { op: "get_microvm", message: "x".into() }, "other", 7),
            (Spawn, BridgeError::SpawnRefused { code: "limit", message: "8 spawns are running (at most 8)".into() }, "spawn_limit", 9),
            (Spawn, BridgeError::HelloRefused { code: "bad_token".into(), message: "m".into() }, "hello_refused", 8),
            (Spawn, BridgeError::SpawnRefused { code: "cwd", message: "no such directory".into() }, "other", 1),
            (Spawn, BridgeError::Transport("socket closed".into()), "other", 8),
            (Spawn, BridgeError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe")), "other", 1),
        ];
        for (step, e, word, code) in cases {
            let shown = e.to_string();
            let f = Failure::from_error(step, e, vm);
            assert_eq!((f.word(), f.exit_code()), (word, code), "{step:?}: {shown}");
            let printed = format!("{PREFIX}{}", f.line());
            assert!(printed.chars().count() <= LINE_MAX && !printed.contains('\n') && !printed.contains(&token), "{printed}");
        }
        assert!(Failure::from_error(Spawn, BridgeError::SpawnRefused { code: "limit", message: String::new() }, vm).line().starts_with("microvm-1 runs 8 commands already"));
        assert!(Failure::from_error(Workspace, BridgeError::NoCapability { cap: "workspace_v1", message: String::new() }, None).line().starts_with("the VM runs an image older than S8"));
        let other = Failure::from_error(TouchId, BridgeError::Cli(CliError::NoKey("keystore key ai-env absent".into())), None);
        assert_eq!(other.line(), "keystore key ai-env absent (at touchid); ai-env doctor checks the setup; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally");
    }

    /// A P0 refusal's fix is in the error's own text (`Refused` adds none):
    /// with no egress connector (P0 always plans vpc egress), the line names
    /// the command that writes it, whole (never cut at [`PART_MAX`]).
    #[test]
    fn a_missing_egress_connector_names_its_fix_before_any_touch_id() {
        let f = Failure::from_error(StartStep::Precheck, BridgeError::EgressRequired, None);
        assert_eq!((f.word(), f.exit_code()), ("refused", 9));
        let line = f.line();
        assert!(line.starts_with("refused before any Touch ID: egress connector required (") && line.ends_with(": make infra-status WRITE=1 writes [aws].egress_connector_arn"), "{line}");
    }
}
