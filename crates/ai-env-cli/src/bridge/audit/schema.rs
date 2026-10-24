//! The audit's registry (S11 schema v2): every event a writer may append to
//! `audit.jsonl`, its detail keys, the keys naming its VMs, where its session
//! comes from and what it means to the cost timeline. Strict mode
//! (`AI_ENV_AUDIT_STRICT=1`, `make test`) refuses a row this registry does not
//! hold; the golden file `tests/fixtures/audit/schema-v2.json` freezes it.
//!
//! The rules:
//! - names and keys are never renamed or removed;
//! - only events and optional keys are added, together with [`EVENTS`] and the
//!   golden file, in one change (`write_the_audit_schema_golden`, run by hand,
//!   whose diff shows nothing removed or renamed);
//! - values stay ids, words and numbers: never a URL, a query, a credential or
//!   a transcript byte (today's exceptions, some paths, phrases and first error
//!   lines, stay as they are, and nothing new adds one);
//! - a writer never passes `actor`: [`super::AuditRow::new`] sets it.
use serde::Serialize;

/// Where an event's session id comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionFrom {
    /// The envelope's `session_id`, as the writer passes it.
    Envelope,
    /// A detail key (`session` or `session_id`); `AuditRow::new` copies a uuid value into the envelope.
    Detail(&'static str),
    /// Neither: `audit tail --session` finds its rows through the session's VMs only.
    None,
}

/// What an event means to the cost timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// The VM began to bill.
    Start,
    Resume,
    Suspend,
    Terminate,
    /// `vm_observed`: as its `state` says.
    Observed,
    /// Restarts the VM's idle clock.
    Activity,
    /// Opens a keep-alive span (a live socket keeps the VM running); activity too.
    SpanOpen,
    /// Closes one; activity too.
    SpanClose,
    ProxyStart,
    ProxyStop,
}

/// When an effect applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "if")]
pub enum When {
    Always,
    /// The detail key holds this value.
    Is { key: &'static str, value: &'static str },
    /// The detail key holds this value, or the row has no such key.
    IsOrAbsent { key: &'static str, value: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CostEffect {
    pub effect: Effect,
    pub when: When,
}

/// One registered event (S11 schema v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventSpec {
    pub name: &'static str,
    /// Keys every row of it carries, beyond `COMMON_REQUIRED`.
    pub required: &'static [&'static str],
    /// Keys a row of it may carry, beyond `COMMON_OPTIONAL`.
    pub optional: &'static [&'static str],
    /// The detail keys naming a VM, the first the one cost charges; a `-` value names none.
    pub vm_keys: &'static [&'static str],
    pub session: SessionFrom,
    /// Empty: cost ignores it.
    pub effects: &'static [CostEffect],
}

/// The constants of the 42 events written as string literals before S11, then
/// part B's two (`vm_observed`, `panel_serve`). `remote::audit_event` and
/// `accounts::audit_event` keep theirs.
pub mod event {
    pub const VM_RUN: &str = "vm_run";
    pub const VM_REUSE: &str = "vm_reuse";
    pub const VM_ADOPT: &str = "vm_adopt";
    pub const VM_SUSPEND: &str = "vm_suspend";
    pub const VM_RESUME: &str = "vm_resume";
    pub const VM_TERMINATE: &str = "vm_terminate";
    pub const VM_TOKEN: &str = "vm_token";
    pub const VM_EGRESS_INTERNET: &str = "vm_egress_internet";
    pub const VM_EGRESS_MISMATCH: &str = "vm_egress_mismatch";
    pub const VM_GC: &str = "vm_gc";
    pub const VM_EXEC: &str = "vm_exec";
    pub const VM_ATTACH: &str = "vm_attach";
    pub const CREDENTIAL_UNSEAL: &str = "credential_unseal";
    pub const CREDENTIAL_GATE: &str = "credential_gate";
    pub const CREDENTIAL_DELIVER: &str = "credential_deliver";
    pub const CREDENTIAL_REJECTED: &str = "credential_rejected";
    pub const AGENT_RECONNECT: &str = "agent_reconnect";
    pub const AGENT_REMINT: &str = "agent_remint";
    pub const AGENT_ROTATE: &str = "agent_rotate";
    pub const ENDPOINT_429: &str = "endpoint_429";
    pub const EGRESS_CHECK: &str = "egress_check";
    pub const EGRESS_RELOAD: &str = "egress_reload";
    pub const EGRESS_ALLOW: &str = "egress_allow";
    pub const EGRESS_SUSPEND: &str = "egress_suspend";
    pub const PROXY_START: &str = "proxy_start";
    pub const PROXY_STOP: &str = "proxy_stop";
    pub const PROXY_PATCH: &str = "proxy_patch";
    pub const CREDS_COMBINED: &str = "creds_combined";
    pub const CREDS_SETUP_TOKEN: &str = "creds_setup_token";
    pub const CREDS_FORGET: &str = "creds_forget";
    pub const CREDS_AWS_SET: &str = "creds_aws_set";
    pub const CREDS_AWS_VERIFY: &str = "creds_aws_verify";
    pub const CREDS_DEPLOYER_KEY: &str = "creds_deployer_key";
    pub const RESUME_SEED_RETRY: &str = "resume_seed_retry";
    pub const RESUME_SEED_MISS: &str = "resume_seed_miss";
    pub const RESUME_SEED_FAILED: &str = "resume_seed_failed";
    pub const REPLAY_TIMEOUT: &str = "replay_timeout";
    pub const OAUTH_REFRESH_ANSWERED: &str = "oauth_refresh_answered";
    pub const SYNTHETIC_OAUTH: &str = "synthetic_oauth";
    pub const LAB_PROBE: &str = "lab_probe";
    pub const INFRA_STATUS_WRITE: &str = "infra_status_write";
    pub const AS_IDENTITY: &str = "as_identity";
    /// S11 (B2): a refresh changed a VM row's recorded `state_seen`: `id`, `state`, `was`, `via`.
    pub const VM_OBSERVED: &str = "vm_observed";
    /// S11 (B1): `panel serve` bound (`started`) or stopped: `port`, `outcome`.
    pub const PANEL_SERVE: &str = "panel_serve";
    /// Every event above, in the registry's order.
    pub const ALL: [&str; 44] = [
        VM_RUN,
        VM_REUSE,
        VM_ADOPT,
        VM_SUSPEND,
        VM_RESUME,
        VM_TERMINATE,
        VM_TOKEN,
        VM_EGRESS_INTERNET,
        VM_EGRESS_MISMATCH,
        VM_GC,
        VM_EXEC,
        VM_ATTACH,
        CREDENTIAL_UNSEAL,
        CREDENTIAL_GATE,
        CREDENTIAL_DELIVER,
        CREDENTIAL_REJECTED,
        AGENT_RECONNECT,
        AGENT_REMINT,
        AGENT_ROTATE,
        ENDPOINT_429,
        EGRESS_CHECK,
        EGRESS_RELOAD,
        EGRESS_ALLOW,
        EGRESS_SUSPEND,
        PROXY_START,
        PROXY_STOP,
        PROXY_PATCH,
        CREDS_COMBINED,
        CREDS_SETUP_TOKEN,
        CREDS_FORGET,
        CREDS_AWS_SET,
        CREDS_AWS_VERIFY,
        CREDS_DEPLOYER_KEY,
        RESUME_SEED_RETRY,
        RESUME_SEED_MISS,
        RESUME_SEED_FAILED,
        REPLAY_TIMEOUT,
        OAUTH_REFRESH_ANSWERED,
        SYNTHETIC_OAUTH,
        LAB_PROBE,
        INFRA_STATUS_WRITE,
        AS_IDENTITY,
        VM_OBSERVED,
        PANEL_SERVE,
    ];
}

/// Required on every v2 row.
pub const COMMON_REQUIRED: [&str; 1] = ["actor"];
/// Allowed on every row: the process's purpose (`vm::cmd::audit_purpose`, S8), which the S4 helpers add.
pub const COMMON_OPTIONAL: [&str; 1] = ["purpose"];
/// `detail.actor`'s words.
pub const ACTORS: [&str; 3] = ["cli", "wrapper", "panel"];

const NO: &[&str] = &[];
const NONE: &[CostEffect] = &[];

const fn always(effect: Effect) -> CostEffect {
    CostEffect { effect, when: When::Always }
}

const fn is(effect: Effect, key: &'static str, value: &'static str) -> CostEffect {
    CostEffect { effect, when: When::Is { key, value } }
}

const fn is_or_absent(effect: Effect, key: &'static str, value: &'static str) -> CostEffect {
    CostEffect { effect, when: When::IsOrAbsent { key, value } }
}

const ACTIVITY: &[CostEffect] = &[always(Effect::Activity)];

const fn ev(name: &'static str, required: &'static [&'static str], optional: &'static [&'static str], vm_keys: &'static [&'static str], session: SessionFrom, effects: &'static [CostEffect]) -> EventSpec {
    EventSpec { name, required, optional, vm_keys, session, effects }
}

use SessionFrom::{Detail, Envelope, None as NoSession};

/// Every event, in this order: `remote::audit_event::ALL` (37), `accounts::audit_event::ALL` (6), [`event::ALL`] (44).
pub static EVENTS: &[EventSpec] = &[
    // ---- remote::audit_event (S8 to S10, A1; then S11 part A's six) ----
    ev("session_remote_start", &["id", "spawn", "gen", "why"], &["account"], &["id"], NoSession, &[always(Effect::SpanOpen)]),
    ev("session_remote_end", &["vm", "spawn", "gen", "exit", "end", "close_ms", "last_acked_seq"], NO, &["vm"], Envelope, &[always(Effect::SpanClose)]),
    ev("session_remote_failed", &["step", "code", "why"], &["gen", "id"], &["id"], NoSession, NONE),
    ev("vm_select", &["id", "choice"], &["how", "ms", "gen", "avoid"], &["id"], NoSession, &[always(Effect::Activity), is(Effect::Resume, "how", "resumed")]),
    ev("seed", &["vm", "outcome", "workspace"], &["mode", "bytes", "ms", "kept", "source"], &["vm"], NoSession, ACTIVITY),
    ev("seed_refused", &["code", "workspace"], &["step", "source", "vm"], &["vm"], NoSession, NONE),
    ev("codeout_fetch", &["vm", "outcome"], &["via", "promoted", "quarantined", "hidden", "bytes", "ms", "why"], &["vm"], NoSession, ACTIVITY),
    ev("box_fetch_finding", &["vm", "ref", "rules"], NO, &["vm"], NoSession, NONE),
    ev("settings_capture", &["phase", "outcome", "vm"], &["files", "why"], &["vm"], Envelope, ACTIVITY),
    ev("settings_sync", &["rules", "policy_lines", "outcome"], NO, NO, Envelope, NONE),
    ev("prewarm", &["workspace", "pid", "setting"], NO, NO, NoSession, NONE),
    ev("auth_timers_unmeasured", &["claude", "measured"], NO, NO, NoSession, NONE),
    ev("box_review", &["repo", "mode", "commits", "findings", "whole_history", "verdict", "ms"], &["remote"], NO, NoSession, NONE),
    ev("hook_install", &["repo", "hook", "outcome"], NO, NO, NoSession, NONE),
    ev("drop_transport", &["session", "wrapper_pid"], NO, NO, Detail("session"), NONE),
    ev("transcript_push", &["session", "vm", "kind", "from", "len", "s3_status", "ms"], &["version_id"], &["vm"], Detail("session"), ACTIVITY),
    ev("transcript_pull", &["session", "vm", "parts", "bytes", "outcome", "ms"], NO, &["vm"], Detail("session"), ACTIVITY),
    ev("transcript_view", &["session", "vm", "messages", "masked", "bytes", "outcome"], NO, &["vm"], Detail("session"), ACTIVITY),
    ev("transcript_stage", &["session", "bytes", "parts", "outcome", "ms"], &["rate", "stored"], NO, Detail("session"), NONE),
    ev("transcript_gc", &["sessions", "objects", "older_than_days"], NO, NO, NoSession, NONE),
    ev("transcript_migrate", &["session", "from", "outcome", "bytes"], NO, NO, Detail("session"), NONE),
    ev("session_move", &["session", "gen", "kind", "from_vm", "outstanding", "cancelled"], &["cause", "trigger", "request"], &["from_vm"], Detail("session"), ACTIVITY),
    ev(
        "session_move_end",
        &["session", "gen", "kind", "outcome", "from_vm", "to_vm", "how", "seed", "transcript", "cut", "touchid", "ms"],
        &["step", "code", "request", "account", "account_from"],
        &["to_vm", "from_vm"],
        Detail("session"),
        ACTIVITY,
    ),
    ev("session_migrate_request", &["session", "nonce", "how"], &["wrapper_pid"], NO, Detail("session"), NONE),
    ev("session_park", &["vm", "spawn", "why", "quiet_ms"], NO, &["vm"], NoSession, &[always(Effect::SpanClose), is(Effect::Suspend, "why", "suspended")]),
    ev("session_unpark", &["vm", "spawn", "by", "vm_state", "ms"], NO, &["vm"], NoSession, &[always(Effect::SpanOpen), is(Effect::Resume, "vm_state", "suspended")]),
    ev("session_park_refused", &["vm", "spawn", "reason", "procs", "cpu_ms"], NO, &["vm"], NoSession, ACTIVITY),
    // The reaped spawn's wrapper died without its session_remote_end: its keep-alive span closes here (B-COST-2).
    ev("session_reap", &["session", "vm", "spawn", "why", "wrapper_pid", "outcome", "ms"], NO, &["vm"], Detail("session"), &[always(Effect::Activity), always(Effect::SpanClose)]),
    ev("vm_gc_reconcile", &["marked", "removed", "closed", "ms"], NO, NO, NoSession, NONE),
    ev("session_account", &["session", "gen", "kind", "from", "from_tag", "to", "to_tag"], NO, NO, Detail("session"), NONE),
    ev("usage_limited", &["account", "tag", "kind", "resets_at", "text", "gen", "source"], NO, NO, Envelope, NONE),
    // A Docker failure's row adds its `attempt` (V's Docker failures since it was last admitted) and its first
    // failing `test` (Mike's retry of a Docker failure, 24 Oct).
    ev("claude_admit", &["version", "outcome", "ms"], &["step", "why", "sha256", "signer", "markers", "docker_image", "auto", "attempt", "test"], NO, NoSession, NONE),
    ev("claude_stage", &["version", "sha256", "outcome", "ms"], &["vm", "s3_status", "step", "why"], &["vm"], NoSession, NONE),
    ev("claude_fetch", &["vm", "version", "sha256", "outcome", "ms"], &["session", "gen", "why", "got_len"], &["vm"], Detail("session"), ACTIVITY),
    ev("claude_object_bad", &["version", "sha256", "vm", "outcome"], &["got_len", "bad_stages"], &["vm"], NoSession, NONE),
    ev("claude_start_failed", &["session", "vm", "version", "sha256", "gen"], &["code", "next"], &["vm"], Detail("session"), NONE),
    ev("argv_dropped", &["flag", "claude", "gen"], &["session", "vm", "ext"], &["vm"], Detail("session"), NONE),
    // ---- accounts::audit_event (A1) ----
    ev("creds_account_adopt", &["name", "tag", "combined"], NO, NO, NoSession, NONE),
    ev("creds_account_use", &["from", "to", "tag", "combined", "chats_other"], NO, NO, NoSession, NONE),
    ev("creds_account_forget", &["name", "files", "holders", "was_active", "failed"], NO, NO, NoSession, NONE),
    ev("account_check", &["account", "tag", "outcome", "status", "five_hour", "seven_day", "kind", "resets_at", "model", "claude", "exit", "ms"], NO, NO, NoSession, NONE),
    ev("creds_account_rename", &["from", "to", "tag"], NO, NO, NoSession, NONE),
    ev("creds_account_note", &["name", "set"], NO, NO, NoSession, NONE),
    // ---- audit::event (the S2 to S8 literals, then S11 part B's two) ----
    ev("vm_run", &["id", "purpose", "image_version", "egress", "shell", "client_token"], &["max_duration_s", "max_idle_s", "suspended_s", "memory_mib"], &["id"], NoSession, &[always(Effect::Start)]),
    ev("vm_reuse", &["id", "purpose", "resumed"], NO, &["id"], NoSession, &[always(Effect::Activity), is(Effect::Resume, "resumed", "true")]),
    ev("vm_adopt", &["id", "client_token", "egress", "via"], NO, &["id"], NoSession, &[always(Effect::Start)]),
    ev("vm_suspend", &["id"], &["by", "outcome", "why", "ms"], &["id"], NoSession, &[is_or_absent(Effect::Suspend, "outcome", "fired")]),
    ev("vm_resume", &["id"], NO, &["id"], NoSession, &[always(Effect::Resume)]),
    ev("vm_terminate", &["id", "by"], NO, &["id"], NoSession, &[always(Effect::Terminate)]),
    ev("vm_token", &["id", "port", "minutes", "revealed"], NO, &["id"], NoSession, NONE),
    ev("vm_egress_internet", &["client_token", "purpose"], NO, NO, NoSession, NONE),
    ev("vm_egress_mismatch", &["id", "expected", "echoed", "via", "purpose", "terminated"], NO, &["id"], NoSession, &[is(Effect::Terminate, "terminated", "true")]),
    ev("vm_gc", &["terminated", "adopted", "removed", "marked", "errors", "include_orphans_s"], NO, NO, NoSession, NONE),
    ev("vm_exec", &["id", "argv0", "spawn", "status", "ms"], NO, &["id"], NoSession, ACTIVITY),
    ev("vm_attach", &["id", "argv0", "spawn", "status", "ms"], NO, &["id"], NoSession, ACTIVITY),
    ev("credential_unseal", &["source", "ms", "outcome"], &["id", "tag", "account", "for"], &["id"], NoSession, NONE),
    ev("credential_gate", &["id", "result"], &["condition", "half", "image_version"], &["id"], NoSession, NONE),
    ev("credential_deliver", &["name", "tag", "source", "deliver"], &["id", "spawn", "account", "to", "gen", "pid"], &["id"], Envelope, ACTIVITY),
    ev("credential_rejected", &["id", "tag", "how"], NO, &["id"], NoSession, NONE),
    ev("agent_reconnect", &["id", "spawn", "reason", "ms"], NO, &["id"], NoSession, ACTIVITY),
    ev("agent_remint", &["id", "spawn", "reason"], NO, &["id"], NoSession, ACTIVITY),
    ev("agent_rotate", &["id", "spawn", "mode"], NO, &["id"], NoSession, ACTIVITY),
    ev("endpoint_429", &["id", "retry_after", "waited_ms"], &["spawn"], &["id"], NoSession, NONE),
    ev("egress_check", &["id", "image_version", "verdict"], &["reason", "revoked", "ready", "allowlisted", "report_only"], &["id"], NoSession, NONE),
    ev("egress_reload", &["result"], NO, NO, NoSession, NONE),
    ev("egress_allow", &["slug", "host", "action"], NO, NO, NoSession, NONE),
    ev("egress_suspend", &["host", "action"], NO, NO, NoSession, NONE),
    ev("proxy_start", &["instance"], NO, NO, NoSession, &[always(Effect::ProxyStart)]),
    ev("proxy_stop", &["instance", "vpc_vms"], NO, NO, NoSession, &[always(Effect::ProxyStop)]),
    ev("proxy_patch", &["instance", "result"], NO, NO, NoSession, NONE),
    ev("creds_combined", &["by", "outcome", "removed"], &["account"], NO, NoSession, NONE),
    ev("creds_setup_token", &["key", "prefix", "chars", "source", "rotated", "combined", "account", "installed"], NO, NO, NoSession, NONE),
    ev("creds_forget", &["files", "failed"], &["accounts", "holders", "holders_unreadable", "ops"], NO, NoSession, NONE),
    ev("creds_aws_set", &["user", "key_id_last4", "key", "rotated", "file"], NO, NO, NoSession, NONE),
    ev("creds_aws_verify", &["user", "key_id_last4", "result"], NO, NO, NoSession, NONE),
    ev("creds_deployer_key", &["user", "key_id_last4", "result"], NO, NO, NoSession, NONE),
    ev("resume_seed_retry", &["session_id", "source"], &["files", "bytes", "kept"], NO, Detail("session_id"), NONE),
    ev("resume_seed_miss", &["session_id", "reason"], NO, NO, Detail("session_id"), NONE),
    ev("resume_seed_failed", &["session_id", "reason"], NO, NO, Detail("session_id"), NONE),
    ev("replay_timeout", &["failed", "gen"], NO, NO, Envelope, NONE),
    ev("oauth_refresh_answered", &["subtype", "gen"], NO, NO, Envelope, NONE),
    ev("synthetic_oauth", &["class", "ms"], NO, NO, Envelope, NONE),
    ev("lab_probe", &["probe", "verdict", "expected"], NO, NO, NoSession, NONE),
    ev("infra_status_write", &["keys_changed", "stack", "bridge_toml"], NO, NO, NoSession, NONE),
    ev("as_identity", &["identity", "command"], &["key_id_last4", "account"], NO, NoSession, NONE),
    ev("vm_observed", &["id", "state", "was", "via"], NO, &["id"], NoSession, &[always(Effect::Observed)]),
    ev("panel_serve", &["port", "outcome"], NO, NO, NoSession, NONE),
];

/// The registered event `name`.
#[must_use]
pub fn spec(name: &str) -> Option<&'static EventSpec> {
    EVENTS.iter().find(|s| s.name == name)
}

/// What strict mode refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    UnknownEvent(String),
    MissingKey { event: String, key: &'static str },
    UnknownKey { event: String, key: String },
    BadActor { event: String, actor: String },
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::UnknownEvent(event) => write!(f, "the event {event} is not registered"),
            Violation::MissingKey { event, key } => write!(f, "{event} lacks its required key {key}"),
            Violation::UnknownKey { event, key } => write!(f, "{event} carries the unregistered key {key}"),
            Violation::BadActor { event, actor } => write!(f, "{event}'s actor {actor} is none of {}", ACTORS.join(", ")),
        }
    }
}

/// A v2 row against the registry: its event registered; every required key and `actor` present;
/// no key outside required, optional and the common ones; `actor` one of `ACTORS`.
pub fn check(row: &super::AuditRow) -> Result<(), Violation> {
    let Some(spec) = spec(&row.event) else {
        return Err(Violation::UnknownEvent(row.event.clone()));
    };
    if let Some(key) = COMMON_REQUIRED.iter().chain(spec.required).find(|k| !row.detail.contains_key(**k)) {
        return Err(Violation::MissingKey { event: row.event.clone(), key });
    }
    let allowed = |k: &str| COMMON_REQUIRED.contains(&k) || COMMON_OPTIONAL.contains(&k) || spec.required.contains(&k) || spec.optional.contains(&k);
    if let Some(key) = row.detail.keys().find(|k| !allowed(k)) {
        return Err(Violation::UnknownKey { event: row.event.clone(), key: key.clone() });
    }
    let actor = row.detail.get("actor").map_or("", String::as_str);
    if !ACTORS.contains(&actor) {
        return Err(Violation::BadActor { event: row.event.clone(), actor: actor.to_string() });
    }
    Ok(())
}

/// The registry as the golden file holds it: `{"v": 2, "common": {…}, "events": [<EventSpec>…]}`.
#[must_use]
pub fn golden() -> serde_json::Value {
    serde_json::json!({
        "v": super::AUDIT_SCHEMA_V,
        "common": {"required": COMMON_REQUIRED, "optional": COMMON_OPTIONAL, "actors": ACTORS},
        "events": EVENTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/audit/schema-v2.json");

    fn golden_text() -> String {
        let mut text = serde_json::to_string_pretty(&golden()).expect("the registry serializes");
        text.push('\n');
        text
    }

    fn snake(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') && !s.starts_with('_') && !s.ends_with('_')
    }

    /// The golden file is the registry, byte for byte: an event or an optional key is added together
    /// with `write_the_audit_schema_golden`'s rewrite, in one change.
    #[test]
    fn the_registry_is_frozen() {
        let on_disk = std::fs::read_to_string(GOLDEN).unwrap_or_else(|e| panic!("{GOLDEN}: {e} (cargo test write_the_audit_schema_golden -- --ignored)"));
        assert!(on_disk == golden_text(), "{GOLDEN} differs from schema::golden(): register the change, then rewrite it (cargo test write_the_audit_schema_golden -- --ignored)");
    }

    /// Rewrites the golden file (by hand, in the change that adds an event or an optional key).
    #[test]
    #[ignore = "rewrites tests/fixtures/audit/schema-v2.json"]
    fn write_the_audit_schema_golden() {
        std::fs::create_dir_all(std::path::Path::new(GOLDEN).parent().unwrap()).unwrap();
        std::fs::write(GOLDEN, golden_text()).unwrap();
    }

    /// The three constant modules, in their order, are `EVENTS`' names; every name is unique and
    /// snake_case, and so is every key.
    #[test]
    fn every_constant_module_name_is_registered() {
        let modules: Vec<&str> = crate::bridge::remote::audit_event::ALL.iter().chain(crate::bridge::accounts::audit_event::ALL.iter()).chain(event::ALL.iter()).copied().collect();
        let names: Vec<&str> = EVENTS.iter().map(|s| s.name).collect();
        assert_eq!(names, modules, "EVENTS is remote::audit_event::ALL, then accounts::audit_event::ALL, then event::ALL");
        assert_eq!(EVENTS.len(), 87);
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "unique names");
        for s in EVENTS {
            assert!(snake(s.name), "{}", s.name);
            let keys: Vec<&str> = s.required.iter().chain(s.optional).copied().collect();
            let set: std::collections::BTreeSet<&str> = keys.iter().copied().collect();
            assert_eq!(set.len(), keys.len(), "{}: a key twice", s.name);
            for k in &keys {
                // `purpose` is common, and four events require it of their own.
                assert!((snake(k) && !COMMON_REQUIRED.contains(k) && !COMMON_OPTIONAL.contains(k)) || (*k == "purpose" && s.required.contains(k)), "{}: {k}", s.name);
            }
            for k in s.vm_keys {
                assert!(keys.contains(k), "{}: the vm key {k} is no key of it", s.name);
            }
            if let SessionFrom::Detail(k) = s.session {
                assert!(keys.contains(&k) && (k == "session" || k == "session_id"), "{}: session from {k}", s.name);
            }
            for e in s.effects {
                if let When::Is { key, .. } | When::IsOrAbsent { key, .. } = e.when {
                    assert!(keys.contains(&key), "{}: the effect's key {key}", s.name);
                }
            }
        }
    }

    /// Each registered name, or its constant, appears at a writer outside the constant modules.
    #[test]
    fn every_registered_event_has_a_writer() {
        // The file without its test modules. A file interleaves them with its writers, so each is cut on
        // its own: a `#[cfg(test)]` (or `#[cfg(all(test, …))]`) line, its further attributes, then
        // `mod name {` at the same indent, through the `}` that closes it at that indent.
        fn without_test_modules(text: &str) -> Vec<&str> {
            let lines: Vec<&str> = text.lines().collect();
            let mut out = Vec::new();
            let mut i = 0;
            while i < lines.len() {
                let line = lines[i];
                let t = line.trim_start();
                let indent = &line[..line.len() - t.len()];
                if t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(all(test") {
                    let mut j = i + 1;
                    while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                        j += 1;
                    }
                    let item = lines.get(j).and_then(|l| l.strip_prefix(indent)).unwrap_or_default();
                    if (item.starts_with("mod ") || item.starts_with("pub(crate) mod ")) && item.ends_with('{') {
                        let close = format!("{indent}}}");
                        let mut k = j + 1;
                        while k < lines.len() && lines[k] != close {
                            k += 1;
                        }
                        i = k + 1;
                        continue;
                    }
                }
                out.push(line);
                i += 1;
            }
            out
        }
        // `use a::b::{X, Y};` also reads as `::X ::Y`: an imported constant is written bare.
        fn with_imports(line: &str) -> String {
            let t = line.trim_start();
            let mut s = line.to_string();
            if t.starts_with("use ") || t.starts_with("pub(crate) use ") {
                if let (Some(a), Some(b)) = (t.find("::{"), t.rfind("};")) {
                    for name in t.get(a + 3..b).unwrap_or_default().split(',') {
                        s.push_str(" ::");
                        s.push_str(name.trim());
                    }
                }
            }
            s
        }
        fn walk(dir: &std::path::Path, out: &mut String) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|e| e == "rs") && !p.ends_with("audit/schema.rs") {
                    let text = std::fs::read_to_string(&p).unwrap();
                    // The writers, not the test modules nor the constants' declarations.
                    for line in without_test_modules(&text).into_iter().filter(|l| !(l.contains("pub const ") && l.contains(": &str = \""))) {
                        out.push_str(&with_imports(line));
                        out.push('\n');
                    }
                }
            }
        }
        let mut src = String::new();
        walk(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bridge")), &mut src);
        // accounts::audit_event's constants are not their names in upper case.
        let accounts = [("creds_account_adopt", "ADOPT"), ("creds_account_use", "USE"), ("creds_account_forget", "FORGET"), ("account_check", "CHECK"), ("creds_account_rename", "RENAME"), ("creds_account_note", "NOTE")];
        let missing: Vec<&str> = EVENTS
            .iter()
            .map(|s| s.name)
            .filter(|name| {
                let constant = accounts.iter().find(|(n, _)| n == name).map_or_else(|| name.to_ascii_uppercase(), |(_, c)| (*c).to_string());
                // A constant's own declaration is `pub const X: &str = "x";`, never `::X`.
                !src.contains(&format!("::{constant}")) && !src.contains(&format!("\"{name}\""))
            })
            .collect();
        assert!(missing.is_empty(), "registered events no writer names: {missing:?}");
    }

    fn row(event: &str, pairs: &[(&str, &str)]) -> super::super::AuditRow {
        let mut r = super::super::AuditRow::new(event, None, super::super::detail(&pairs.iter().map(|(k, v)| (*k, (*v).to_string())).collect::<Vec<_>>()));
        r.detail.insert("actor".into(), "cli".into());
        r
    }

    #[test]
    fn check_names_each_violation() {
        assert_eq!(check(&row("replay_timeout", &[("failed", "1"), ("gen", "2")])), Ok(()));
        assert_eq!(check(&row("replay_timeout", &[("failed", "1"), ("gen", "2"), ("purpose", "session")])), Ok(()), "purpose is common");
        assert_eq!(check(&row("vm_test", &[])), Err(Violation::UnknownEvent("vm_test".into())));
        assert_eq!(check(&row("replay_timeout", &[("failed", "1")])), Err(Violation::MissingKey { event: "replay_timeout".into(), key: "gen" }));
        assert_eq!(check(&row("replay_timeout", &[("failed", "1"), ("gen", "2"), ("x", "y")])), Err(Violation::UnknownKey { event: "replay_timeout".into(), key: "x".into() }));
        let mut bad = row("replay_timeout", &[("failed", "1"), ("gen", "2")]);
        bad.detail.insert("actor".into(), "robot".into());
        assert_eq!(check(&bad), Err(Violation::BadActor { event: "replay_timeout".into(), actor: "robot".into() }));
        bad.detail.remove("actor");
        assert_eq!(check(&bad), Err(Violation::MissingKey { event: "replay_timeout".into(), key: "actor" }));
        assert!(Violation::UnknownKey { event: "e".into(), key: "k".into() }.to_string().contains("unregistered key k"));
    }

    /// The golden form of the enums: `"envelope"`, `{"detail": "session"}`, `"none"`; `{"if": "always"}`,
    /// `{"if": "is", "key": …, "value": …}`.
    #[test]
    fn the_golden_form_of_sessions_and_effects() {
        let g = golden();
        assert_eq!(g["v"], 2);
        assert_eq!(g["common"]["actors"], serde_json::json!(["cli", "wrapper", "panel"]));
        let of = |name: &str| g["events"].as_array().unwrap().iter().find(|e| e["name"] == name).cloned().unwrap();
        assert_eq!(of("session_remote_end")["session"], "envelope");
        assert_eq!(of("transcript_pull")["session"], serde_json::json!({"detail": "session"}));
        assert_eq!(of("vm_run")["session"], "none");
        assert_eq!(of("vm_run")["effects"], serde_json::json!([{"effect": "start", "when": {"if": "always"}}]));
        assert_eq!(of("vm_suspend")["effects"][0]["when"], serde_json::json!({"if": "is_or_absent", "key": "outcome", "value": "fired"}));
        assert_eq!(of("vm_reuse")["effects"][1]["when"], serde_json::json!({"if": "is", "key": "resumed", "value": "true"}));
    }
}
