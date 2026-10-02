//! `ai-env egress …` and `ai-env proxy …` (S5): the operator commands over
//! the shared proxy. Every AWS call is the aws CLI as the operator
//! (`bridge::awscli`, region and endpoint pinned), never the runtime key;
//! the stack's ids come from `state/infra.toml` only (`make infra-status
//! WRITE=1` writes it), never from Pulumi. `ai-env egress check` lives in
//! `egress::check`.
//!
//! Every command but `egress env` loads `bridge.toml` (the S5 keys
//! validated) and `state/infra.toml`, then checks, before its first other
//! aws call, that the CLI's credentials belong to the account of
//! `[aws].egress_connector_arn` (exit 1 otherwise). No Touch ID, no SDK.
//!
//! - `egress status`: one row per check (ok | DRIFT | unknown) of the
//!   connector, its ENIs, the VM subnet's effective route table and network
//!   ACL, the three security groups, the VPC (IPv6, DNS attributes, the DNS
//!   Firewall in `firewall` mode, DHCP servers, endpoints, peering, NAT), the
//!   proxy instance, its SSM agent, squid, the parameter hashes
//!   `ai-env-proxy-reload --status` prints, and `squid.conf`/`allow` against
//!   what the stack rendered. Drift is exit 1; anything that could not be
//!   verified (and no drift) is exit 7; only a stopped proxy's skipped
//!   checks are neither.
//! - `egress allow|suspend` edit the `extras`/`suspended` parameters under
//!   `state/egress.lock`: the three lists are read in one call (a value that
//!   does not parse is never overwritten), the effective set ((allow ∪
//!   extras) − suspended) decides what is said, a value over 4 KB is refused
//!   before any write, the put must advance the version by exactly one
//!   (else the parameter's history says which hosts the overwrite allowed
//!   again), then the proxy reloads; after a removal or a suspension its
//!   `--status` must show the written value applied before anything is
//!   claimed about the proxy. Any failure there prints [`STILL_ALLOWED`]
//!   (when the host left the effective set, or an overwrite allowed hosts
//!   again) and exits 7.
//! - `egress reload` (under the same lock), `egress env` (no AWS call).
//! - `proxy stop` (refused while a registry row may run a vpc VM, unless
//!   `--yes`: exit 9; then waits for `stopped`), `proxy start` (waits for
//!   running, SSM Online and squid serving the current parameters), `proxy
//!   patch` (`dnf -y upgrade --security --releasever=latest` through SSM —
//!   the AMI's locked release alone sees no update —, the release and squid
//!   printed before and after, a squid restart, then the same proof).
//! - A proxy id that is terminated or unknown to EC2 (the stack replaces the
//!   instance on any user-data change) means `state/infra.toml` is stale:
//!   every command says so and names `make infra-status WRITE=1`.
use super::ops::{self, arr, text, Invocation, Param, Wait, PATCH_EXEC_S, RELOAD, RELOAD_EXEC_S, STATUS_EXEC_S};
use super::{
    fits_parameter, is_valid_slug, normalize_connector, normalize_host, param_name, parse_extras, parse_hosts, parse_reload_status, proxy_env, render_extras, render_suspended, value_sha256, Extra, PARAMETER_PREFIX, PARAMS,
    PARAM_MAX_BYTES, PROXY_PORT, RESOLVERS,
};
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::awscli::require_operator_account;
use crate::bridge::config::{is_rfc1918, BridgeConfig, Paths};
use crate::bridge::infra::{read_infra_state, InfraState};
use crate::bridge::registry::read_regular_file;
use crate::bridge::vm::lock::lock_exclusive;
use crate::bridge::vm::registry::{list_rows, RowStatus, VmRow};
use crate::cli::{EgressCmd, ProxyCmd};
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

/// `ai-env egress …`.
pub fn main(store: &Keystore, cmd: EgressCmd) -> Result<()> {
    match cmd {
        EgressCmd::Status { json } => status(json),
        EgressCmd::Allow { slug, host, remove } => allow(&slug, &host, remove),
        EgressCmd::Suspend { host, restore } => suspend(&host, restore),
        EgressCmd::Reload { if_changed } => reload(if_changed),
        EgressCmd::Env { shell } => env(shell),
        EgressCmd::Check { vm, keep, json, if_needed } => super::check::cmd_check(store, vm.as_deref(), keep, json, if_needed),
    }
}

/// `ai-env proxy …`.
pub fn proxy_main(cmd: ProxyCmd) -> Result<()> {
    match cmd {
        ProxyCmd::Stop { yes } => proxy_stop(yes),
        ProxyCmd::Start => proxy_start(),
        ProxyCmd::Patch => proxy_patch(),
    }
}

/// The line a failed removal or suspension prints on stderr, alone: the
/// proxy may still serve the host.
pub const STILL_ALLOWED: &str = "STILL ALLOWED on the proxy; `make proxy-stop` to fail closed";

/// The line any other reload prints on stderr, alone, when what the proxy
/// serves is unknown (exit 3: the install and its rollback failed; a
/// timeout; an exit outside the script's).
pub const PROXY_STATE_UNKNOWN: &str = "the proxy's state is unknown: `make proxy-stop` to fail closed";

/// How long `allow`, `suspend` and `reload` wait for `state/egress.lock`
/// (its holder may be waiting for a reload on the proxy).
const LOCK_BUDGET: Duration = Duration::from_secs(1200);

const HINT: &str = "run `make infra-status WRITE=1`";

/// The lists `egress allow|suspend` read together: what decides whether a host is served.
const LISTS: [&str; 3] = ["allow", "extras", "suspended"];

// ---- context ----------------------------------------------------------------------------

/// What an operator command works from.
struct Ctx {
    paths: Paths,
    cfg: BridgeConfig,
    state: InfraState,
    /// `[aws].egress_connector_arn`: the operator's account is its account.
    connector: String,
    /// `AI_ENV_BRIDGE_LAB_BACKOFF_MS` (debug builds): polls in milliseconds.
    backoff_ms: Option<u64>,
}

impl Ctx {
    /// `bridge.toml` (must exist; the S5 keys valid; the connector set) and
    /// `state/infra.toml` (must exist): exit 1 with the hint otherwise.
    fn load() -> Result<Ctx> {
        let paths = Paths::resolve()?;
        let cfg = BridgeConfig::load(&paths)?.ok_or_else(|| CliError::Msg(format!("{} not found: {HINT} (it writes [aws])", paths.config.display())))?;
        cfg.aws.validate_egress()?;
        let connector = cfg.aws.egress_connector_arn.as_deref().map(str::trim).filter(|a| !a.is_empty()).map(str::to_string);
        let connector = connector.ok_or_else(|| CliError::Msg(format!("[aws].egress_connector_arn is not set in {}: {HINT} (the operator's account is the connector's)", paths.config.display())))?;
        let state = read_infra_state(&paths)?
            .ok_or_else(|| CliError::Msg(format!("{} not found: {HINT} (the egress and proxy commands read the stack's ids from it, never from Pulumi)", paths.infra_state().display())))?;
        let backoff_ms = crate::bridge::lab::vm_knobs().backoff_ms;
        if backoff_ms.is_some() {
            note("LAB KNOB ACTIVE (AI_ENV_BRIDGE_LAB_BACKOFF_MS): polls scaled to milliseconds (debug build)");
        }
        Ok(Ctx { paths, cfg, state, connector, backoff_ms })
    }

    /// The S5 field `name` of `state/infra.toml`; with a `prefix` it must be
    /// an AWS id of that kind (`i-`, `sg-`, …: never anything the aws CLI
    /// could read as an option).
    fn need<'a>(&self, name: &str, value: &'a Option<String>, prefix: &str) -> Result<&'a str> {
        let path = self.paths.infra_state();
        let v = value.as_deref().map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| CliError::Msg(format!("{} has no {name} (written before S5?): {HINT}", path.display())))?;
        if !prefix.is_empty() && !is_aws_id(v, prefix) {
            return Err(CliError::Msg(format!("{} {name} = {v:?} is not a {prefix}… id: {HINT}", path.display())));
        }
        Ok(v)
    }

    fn instance(&self) -> Result<&str> {
        self.need("proxy_instance_id", &self.state.proxy_instance_id, "i-")
    }

    /// The parameters this build edits are `PARAMETER_PREFIX/…`: the stack's
    /// prefix must be the same.
    fn check_prefix(&self) -> Result<()> {
        let p = self.need("parameter_prefix", &self.state.parameter_prefix, "")?;
        if p == PARAMETER_PREFIX {
            Ok(())
        } else {
            Err(CliError::Msg(format!("{} parameter_prefix = {p:?}, but this ai-env manages {PARAMETER_PREFIX}: {HINT}, or update ai-env", self.paths.infra_state().display())))
        }
    }

    /// The operator-account check, before any other aws call (exit 1).
    fn operator(&self, what: &str) -> Result<()> {
        require_operator_account(&self.connector).map(|_| ()).map_err(|e| CliError::Msg(format!("{what}: {e}")))
    }

    fn wait(&self, w: Wait) -> Wait {
        w.scaled(self.backoff_ms)
    }

    /// The bridge's private `state/` directory (the put-parameter temp file goes there).
    fn state_dir(&self) -> PathBuf {
        self.paths.egress_lock().parent().map_or_else(|| self.paths.root.join("state"), std::path::Path::to_path_buf)
    }
}

/// `prefix` followed by 8 or 17 lowercase hex digits (`i-0123456789abcdef0`).
fn is_aws_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|h| matches!(h.len(), 8 | 17) && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// 64 lowercase hex digits.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// The proxy's address: `[aws].proxy_private_ip`, else the state's
/// `proxy_private_ip`, else [`PROXY_IP`] (RFC 1918 values only).
fn proxy_ip(cfg: &BridgeConfig, state: Option<&InfraState>) -> String {
    super::effective_proxy_ip(cfg.aws.proxy_private_ip.as_deref(), state).0.to_string()
}

/// One `ai-env: …` line on stderr (never a panic on a closed pipe).
fn note(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "ai-env: {line}");
}

/// One line on stdout, best effort: unlike `outln!`, a closed pipe never
/// ends a command early, so a reload still runs after the parameter write
/// and the exit code still says what happened (drift, a failed reload).
fn say(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// One line on stderr, alone (the fail-closed lines).
fn alone(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// One audit row (`actor=cli`); a failure to write is a warning (what it
/// records already happened). Never a parameter value.
fn audit(paths: &Paths, event: &str, pairs: &[(&str, String)]) {
    let mut d = audit::detail(pairs);
    d.insert("actor".into(), "cli".into());
    if let Err(e) = audit::append(&paths.audit(), &AuditRow::new(event, None, d)) {
        note(&format!("warning: audit row {event} not written: {e}"));
    }
}

/// An aws failure of `what`: exit 7.
fn aws(what: &str) -> impl Fn(String) -> CliError + '_ {
    move |e| CliError::Aws(format!("{what}: {e}"))
}

/// Hold `state/egress.lock` around `f`: every read-modify-write of the
/// proxy's parameters and every reload, so two operators never lose each
/// other's edit.
fn locked<T>(paths: &Paths, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().map_err(|e| CliError::Msg(format!("cannot start the async runtime: {e}")))?;
    let guard = rt.block_on(lock_exclusive(&paths.egress_lock(), LOCK_BUDGET, "the egress lock"))?;
    let out = f();
    drop(guard);
    out
}

// ---- the proxy instance -----------------------------------------------------------------

/// What `state/infra.toml`'s proxy id names now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProxyState {
    /// `pending`, `running`, `stopping`, `stopped`.
    Live(String),
    /// Terminated, shutting down, or unknown to EC2: the stack replaced it
    /// (any user-data change does) and the state file is stale.
    Gone,
}

/// The proxy's state; `Err` when it could not be read.
pub(super) fn proxy_state(instance: &str) -> std::result::Result<ProxyState, String> {
    match ops::instance_state(instance) {
        Ok(s) if matches!(s.as_str(), "terminated" | "shutting-down") => Ok(ProxyState::Gone),
        Ok(s) => Ok(ProxyState::Live(s)),
        Err(e) if e.contains("InvalidInstanceID.NotFound") => Ok(ProxyState::Gone),
        Err(e) => Err(e),
    }
}

/// What a command says about a proxy id that no longer exists.
pub(super) fn proxy_gone(instance: &str) -> String {
    format!("state/infra.toml names a proxy that no longer exists ({instance}): {HINT} (the stack's current proxy may still serve the old list)")
}

/// The proxy's state for `proxy stop|start|patch`: a gone proxy is exit 1
/// (the state file is stale), an unreadable one exit 7.
fn live_proxy(what: &str, instance: &str) -> Result<String> {
    match proxy_state(instance) {
        Ok(ProxyState::Live(s)) => Ok(s),
        Ok(ProxyState::Gone) => Err(CliError::Msg(format!("{what}: {}", proxy_gone(instance)))),
        Err(e) => Err(CliError::Aws(format!("{what}: {e}"))),
    }
}

// ---- the reload on the proxy ------------------------------------------------------------

/// What asking the proxy to reload came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reload {
    /// SSM `Success` and exit 0: applied, or (`--if-changed`) nothing changed
    /// since the last apply.
    Applied { unchanged: bool, line: String },
    /// The instance is stopped (or stopping, unless the change must stop a
    /// host being served): the boot reload applies the parameters.
    Stopped(String),
    /// `Failed`, exit 1: the old config keeps serving.
    Refused(String),
    /// `Failed`, exit 2: the proxy could not read its parameters; nothing changed.
    FetchFailed(String),
    /// Exit 3 (the install and its rollback failed), a timeout, a cancel,
    /// any other exit: what squid serves is unknown.
    StateUnknown(String),
    /// `state/infra.toml` names a proxy that no longer exists.
    Gone(String),
    /// Not run (the instance starting, SSM unreachable).
    Failed(String),
}

impl Reload {
    /// The audit `result`.
    fn result(&self) -> &'static str {
        match self {
            Reload::Applied { unchanged: false, .. } => "applied",
            Reload::Applied { unchanged: true, .. } => "unchanged",
            Reload::Stopped(_) => "proxy-stopped",
            Reload::Refused(_) => "refused",
            Reload::FetchFailed(_) => "fetch-failed",
            Reload::StateUnknown(_) => "state-unknown",
            Reload::Gone(_) => "proxy-gone",
            Reload::Failed(_) => "failed",
        }
    }

    /// Why it failed, `None` when it did not.
    fn failure(&self) -> Option<&str> {
        match self {
            Reload::Refused(m) | Reload::FetchFailed(m) | Reload::StateUnknown(m) | Reload::Gone(m) | Reload::Failed(m) => Some(m),
            Reload::Applied { .. } | Reload::Stopped(_) => None,
        }
    }
}

/// The stderr line of a failed reload, alone, before the error: [`STILL_ALLOWED`]
/// when the host must stop being served (`still_allowed`), else
/// [`PROXY_STATE_UNKNOWN`] when what the proxy serves is unknown.
fn fail_closed_line(reload: &Reload, still_allowed: bool) {
    if reload.failure().is_none() {
        return;
    }
    if still_allowed {
        alone(STILL_ALLOWED);
    } else if matches!(reload, Reload::StateUnknown(_)) {
        alone(PROXY_STATE_UNKNOWN);
    }
}

/// `ai-env-proxy-reload [--if-changed]` on the proxy through SSM when the
/// instance runs (its `--status` is a command of its own: [`status_line`]).
/// `deny`: the change must stop a host being served, so a `stopping` proxy
/// (still serving) is a failure, not a stop.
fn reload_proxy(ctx: &Ctx, instance: &str, if_changed: bool, comment: &str, deny: bool) -> Reload {
    let state = match proxy_state(instance) {
        Ok(ProxyState::Live(s)) => s,
        Ok(ProxyState::Gone) => return Reload::Gone(proxy_gone(instance)),
        Err(e) => return Reload::Failed(e),
    };
    match state.as_str() {
        "running" => {}
        "stopped" => return Reload::Stopped(state),
        "stopping" if !deny => return Reload::Stopped(state),
        other => return Reload::Failed(format!("the proxy {instance} is {other}: not reloaded (`ai-env egress reload` once it runs or has stopped)")),
    }
    let cmd = format!("{RELOAD}{}", if if_changed { " --if-changed" } else { "" });
    let inv = match ops::run_shell(instance, &[&cmd], comment, RELOAD_EXEC_S, ctx.wait(Wait::RELOAD)) {
        Ok(inv) => inv,
        Err(e) => return Reload::Failed(e),
    };
    let last = inv.last_line().to_string();
    match (inv.status.as_str(), inv.code) {
        ("Success", 0) => Reload::Applied { unchanged: if_changed && inv.stderr.contains("unchanged since the last apply"), line: last },
        ("Failed", 1) => Reload::Refused(format!("the reload was refused (exit 1): the proxy kept its old config ({last})")),
        ("Failed", 2) => Reload::FetchFailed(format!("the proxy could not fetch its parameters (exit 2): nothing changed ({last})")),
        (_, 3) => Reload::StateUnknown(format!("the install failed and its rollback too (exit 3): what squid serves is unknown ({last})")),
        (s, c) => Reload::StateUnknown(format!("the reload ended {s} (exit {c}): what squid serves is unknown ({last})")),
    }
}

/// After a removal or a suspension: the proxy's `--status`, taken after the
/// reload, must show the new value applied (`applied=yes`, and
/// `sha256_<param>` the hash of the value written).
fn verify_applied(status: Option<&BTreeMap<String, String>>, param: &str, value: &str) -> std::result::Result<(), String> {
    let Some(st) = status else { return Err("the proxy printed no --status line after it".into()) };
    let applied = st.get("applied").map(String::as_str);
    if applied != Some("yes") {
        return Err(format!("the proxy's --status says applied={}", applied.unwrap_or("(none)")));
    }
    match st.get(&format!("sha256_{param}")) {
        Some(h) if *h == value_sha256(value) => Ok(()),
        Some(_) => Err(format!("the proxy's --status shows another {param} than the one written")),
        None => Err(format!("the proxy's --status has no sha256_{param}")),
    }
}

// ---- egress allow / suspend / reload / env ----------------------------------------------

/// `allow`, `extras` and `suspended` as SSM holds them now.
struct Lists {
    allow: Vec<String>,
    extras: Vec<Extra>,
    suspended: BTreeSet<String>,
    /// The exact values and their versions.
    raw: BTreeMap<&'static str, Param>,
}

impl Lists {
    fn raw(&self, param: &str) -> &Param {
        &self.raw[param]
    }

    /// The hosts the proxy serves, (allow ∪ extras) − suspended, with `param`
    /// (`extras` or `suspended`) holding `value` instead of what was read.
    fn effective_with(&self, param: &str, value: &str) -> std::result::Result<BTreeSet<String>, String> {
        let extras: Vec<String> = if param == "extras" { parse_extras(value)?.into_iter().map(|e| e.host).collect() } else { self.extras.iter().map(|e| e.host.clone()).collect() };
        let suspended: BTreeSet<String> = if param == "suspended" { parse_hosts(value)?.into_iter().collect() } else { self.suspended.clone() };
        Ok(self.allow.iter().chain(extras.iter()).filter(|h| !suspended.contains(*h)).cloned().collect())
    }
}

/// The three lists in one `get-parameters`; any of them that does not parse
/// is exit 1 (nothing is written), a missing one exit 7.
fn read_lists(what: &str) -> Result<Lists> {
    let names: Vec<String> = LISTS.iter().map(|p| param_name(p)).collect();
    let (mut got, missing) = ops::get_parameters(&names).map_err(aws(what))?;
    if !missing.is_empty() {
        return Err(CliError::Aws(format!("{what}: SSM has no {} (is the S5 stack deployed? make deploy)", missing.join(", "))));
    }
    let mut raw = BTreeMap::new();
    for p in LISTS {
        let v = got.remove(&param_name(p)).ok_or_else(|| CliError::Aws(format!("{what}: {} is not in the get-parameters answer", param_name(p))))?;
        raw.insert(p, v);
    }
    let bad = |p: &str, e: String| CliError::Msg(format!("{what}: {} does not parse ({e}); nothing was written: correct it first (aws ssm put-parameter)", param_name(p)));
    let allow = parse_hosts(&raw["allow"].value).map_err(|e| bad("allow", e))?;
    let extras = parse_extras(&raw["extras"].value).map_err(|e| bad("extras", e))?;
    let suspended = parse_hosts(&raw["suspended"].value).map_err(|e| bad("suspended", e))?.into_iter().collect();
    Ok(Lists { allow, extras, suspended, raw })
}

/// One edit of `extras` or `suspended`.
struct Edit<'a> {
    what: &'a str,
    /// The lists as read (the version check's diff needs them).
    lists: &'a Lists,
    param: &'static str,
    /// What the parameter holds after the edit (the value read when unchanged).
    value: String,
    changed: bool,
    /// A removal or a suspension: the host must stop being served.
    deny: bool,
    /// After the edit the host is outside (allow ∪ extras) − suspended.
    gone: bool,
    /// What the lists say now, printed once written (or found unchanged).
    message: String,
    /// What the proxy does now, printed only after the reload is proved.
    claim: Option<String>,
    /// The audit row of the write.
    event: &'static str,
    pairs: Vec<(&'static str, String)>,
}

/// After a put answered `version`, not one more than the version read:
/// the hosts this overwrite allowed again — served with the value read and
/// with the value written, but not with the version it replaced (another
/// writer's newest, from the parameter's history), so the other writer had
/// removed or suspended them. A host this edit itself adds is not one.
fn reallowed(lists: &Lists, param: &str, name: &str, written: &str, version: u64) -> std::result::Result<Vec<String>, String> {
    let history = ops::parameter_history(name)?;
    let (_, replaced) = history.range(..version).next_back().ok_or_else(|| format!("{name} has no version before {version}"))?;
    let read = lists.effective_with(param, &lists.raw(param).value)?;
    let ours = lists.effective_with(param, written)?;
    let theirs = lists.effective_with(param, replaced)?;
    Ok(ours.intersection(&read).filter(|h| !theirs.contains(*h)).cloned().collect())
}

/// Write the edit (4 KB cap first, then the version check), reload the
/// proxy, and for a removal or a suspension prove with its `--status` that
/// it serves the written value. Exit 7 on any failure after the cap, with
/// [`STILL_ALLOWED`] when the host left the effective set, or when an
/// overwrite of another writer's version allowed hosts again.
fn apply_edit(ctx: &Ctx, instance: &str, e: Edit<'_>) -> Result<()> {
    let name = param_name(e.param);
    let still = e.deny && e.gone;
    if e.changed {
        if !fits_parameter(&e.value) {
            let hint = if e.param == "extras" { " (remove unused entries first: ai-env egress allow SLUG HOST --remove)" } else { "" };
            return Err(CliError::Msg(format!("{}: {name} would be {} bytes, over the {PARAM_MAX_BYTES}-byte standard tier; nothing was written{hint}", e.what, e.value.len())));
        }
        let version = match ops::put_parameter(&ctx.state_dir(), &name, &e.value) {
            Ok(v) => v,
            Err(err) => {
                // A timeout may have landed the write; either way the proxy was not reloaded.
                if still {
                    alone(STILL_ALLOWED);
                }
                return Err(CliError::Aws(format!("{}: {err}", e.what)));
            }
        };
        audit(&ctx.paths, e.event, &e.pairs);
        let read = e.lists.raw(e.param).version;
        if version != read + 1 {
            let detail = match reallowed(e.lists, e.param, &name, &e.value, version) {
                Ok(hosts) if hosts.is_empty() => {
                    if still {
                        alone(STILL_ALLOWED);
                    }
                    String::new()
                }
                Ok(hosts) => {
                    alone(STILL_ALLOWED);
                    for h in &hosts {
                        note(&format!("{h}: allowed again by this overwrite (the other writer had removed or suspended it)"));
                    }
                    format!("; it allowed again {}", hosts.join(", "))
                }
                Err(err) => {
                    alone(STILL_ALLOWED);
                    format!("; what it allowed again is unknown ({err})")
                }
            };
            return Err(CliError::Aws(format!("{}: another writer changed {name} at the same time (version {read} became {version}, not {}){detail}: re-run", e.what, read + 1)));
        }
    }
    say(&e.message);
    let r = reload_proxy(ctx, instance, false, e.what, e.deny);
    audit(&ctx.paths, "egress_reload", &[("result", r.result().to_string())]);
    let held = if e.changed { format!("{name} is written") } else { format!("{name} already holds it") };
    match &r {
        Reload::Applied { line, .. } => {
            if e.deny {
                let proof = match status_line(ctx, instance, e.what) {
                    Ok(st) => verify_applied(st.as_ref().map(|(_, pairs)| pairs), e.param, &e.value),
                    Err(err) => Err(format!("its --status could not be read ({err})")),
                };
                if let Err(why) = proof {
                    if still {
                        alone(STILL_ALLOWED);
                    }
                    return Err(CliError::Aws(format!("{}: {held} and the reload exited 0, but {why}; `ai-env egress reload` retries", e.what)));
                }
                say(&format!("proxy: reloaded and verified ({line})"));
            } else {
                say(&format!("proxy: reloaded ({line})"));
            }
            if let Some(claim) = e.claim.as_deref().filter(|_| e.deny) {
                say(claim);
            }
            Ok(())
        }
        Reload::Stopped(state) => {
            say(&format!("the proxy is {state}: the change applies at its next start (`ai-env proxy start`)"));
            Ok(())
        }
        _ => {
            fail_closed_line(&r, still);
            Err(CliError::Aws(format!("{}: {held}, but {}; `ai-env egress reload` retries", e.what, r.failure().unwrap_or("the reload failed"))))
        }
    }
}

/// Add (or remove) `slug` on `host`'s line; a host without a slug is
/// dropped. `true` when the list changed.
fn edit_extras(extras: &mut Vec<Extra>, slug: &str, host: &str, remove: bool) -> bool {
    let at = extras.iter().position(|e| e.host == host);
    match (at, remove) {
        (Some(i), false) => extras[i].slugs.insert(slug.to_string()),
        (None, false) => {
            extras.push(Extra { host: host.to_string(), slugs: BTreeSet::from([slug.to_string()]) });
            true
        }
        (Some(i), true) => {
            let removed = extras[i].slugs.remove(slug);
            if extras[i].slugs.is_empty() {
                extras.remove(i);
            }
            removed
        }
        (None, true) => false,
    }
}

fn allow(slug: &str, host: &str, remove: bool) -> Result<()> {
    if !is_valid_slug(slug) {
        return Err(CliError::Usage(format!("egress allow: {slug:?} is not a workspace slug (1–64 of A-Z a-z 0-9 . _ -)")));
    }
    let host = normalize_host(host).map_err(|e| CliError::Usage(format!("egress allow: {e}")))?;
    let ctx = Ctx::load()?;
    ctx.check_prefix()?;
    let instance = ctx.instance()?;
    let what = if remove { "egress allow --remove" } else { "egress allow" };
    ctx.operator(what)?;
    locked(&ctx.paths, || {
        let l = read_lists(what)?;
        let mut extras = l.extras.clone();
        let changed = edit_extras(&mut extras, slug, &host, remove);
        let name = param_name("extras");
        let in_base = l.allow.contains(&host);
        let suspended = l.suspended.contains(&host);
        let listed_by: Vec<String> = extras.iter().find(|e| e.host == host).map(|e| e.slugs.iter().cloned().collect()).unwrap_or_default();
        let effective = (in_base || !listed_by.is_empty()) && !suspended;
        let mut message = match (remove, changed) {
            (false, true) => format!("allowed {host} for {slug} ({} extra host(s) in {name})", extras.len()),
            (false, false) => format!("{host} is already allowed for {slug}; nothing written"),
            (true, true) => format!("removed {host} for {slug}"),
            (true, false) => format!("{host} is not listed for {slug}; nothing written"),
        };
        if remove && effective {
            let why: Vec<String> = [in_base.then(|| "in the base allowlist".to_string()), (!listed_by.is_empty()).then(|| format!("still listed by {}", listed_by.join(", ")))].into_iter().flatten().collect();
            message.push_str(&format!("; it stays allowed: {}", why.join(", ")));
        } else if remove {
            message.push_str(if suspended { "; it is suspended" } else { "; no workspace lists it any more" });
        } else if suspended {
            message.push_str(&format!("; it stays denied: suspended (ai-env egress suspend {host} --restore)"));
        } else if in_base {
            message.push_str("; it is in the base allowlist too");
        }
        let value = if changed { render_extras(&extras) } else { l.raw("extras").value.clone() };
        let claim = (remove && !effective).then(|| format!("the proxy denies {host} now"));
        let pairs = vec![("slug", slug.to_string()), ("host", host.clone()), ("action", (if remove { "remove" } else { "add" }).to_string())];
        apply_edit(&ctx, instance, Edit { what, lists: &l, param: "extras", value, changed, deny: remove, gone: !effective, message, claim, event: "egress_allow", pairs })
    })
}

fn suspend(host: &str, restore: bool) -> Result<()> {
    let host = normalize_host(host).map_err(|e| CliError::Usage(format!("egress suspend: {e}")))?;
    let ctx = Ctx::load()?;
    ctx.check_prefix()?;
    let instance = ctx.instance()?;
    let what = if restore { "egress suspend --restore" } else { "egress suspend" };
    ctx.operator(what)?;
    locked(&ctx.paths, || {
        let l = read_lists(what)?;
        let mut hosts = l.suspended.clone();
        let changed = if restore { hosts.remove(&host) } else { hosts.insert(host.clone()) };
        let name = param_name("suspended");
        let listed = l.allow.contains(&host) || l.extras.iter().any(|e| e.host == host);
        let message = match (restore, changed) {
            (false, true) => format!("suspended {host} ({} host(s) in {name})", hosts.len()),
            (false, false) => format!("{host} is already suspended; nothing written"),
            (true, true) if listed => format!("restored {host}: an allowlist lists it"),
            (true, true) => format!("restored {host}; it is in no allowlist"),
            (true, false) => format!("{host} is not suspended; nothing written"),
        };
        let value = if changed { render_suspended(&hosts.iter().cloned().collect::<Vec<_>>()) } else { l.raw("suspended").value.clone() };
        let claim = (!restore).then(|| format!("the proxy denies {host} now"));
        let pairs = vec![("host", host.clone()), ("action", (if restore { "restore" } else { "suspend" }).to_string())];
        apply_edit(&ctx, instance, Edit { what, lists: &l, param: "suspended", value, changed, deny: !restore, gone: !restore, message, claim, event: "egress_suspend", pairs })
    })
}

fn reload(if_changed: bool) -> Result<()> {
    let ctx = Ctx::load()?;
    let instance = ctx.instance()?;
    ctx.operator("egress reload")?;
    locked(&ctx.paths, || {
        let r = reload_proxy(&ctx, instance, if_changed, "ai-env egress reload", false);
        audit(&ctx.paths, "egress_reload", &[("result", r.result().to_string())]);
        match &r {
            Reload::Applied { unchanged, line } => say(&format!("proxy {instance}: {} ({line})", if *unchanged { "unchanged since the last apply" } else { "applied" })),
            Reload::Stopped(state) => say(&format!("the proxy is {state}: it reads its parameters when it starts (`ai-env proxy start`)")),
            Reload::Refused(m) | Reload::FetchFailed(m) | Reload::StateUnknown(m) | Reload::Gone(m) | Reload::Failed(m) => {
                fail_closed_line(&r, false);
                return Err(CliError::Aws(format!("egress reload: {m}")));
            }
        }
        Ok(())
    })
}

fn env(shell: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    cfg.aws.validate_egress()?;
    let state = read_infra_state(&paths)?;
    for (k, v) in proxy_env(&proxy_ip(&cfg, state.as_ref()), PROXY_PORT) {
        if shell {
            outln!("export {k}='{v}'");
        } else {
            outln!("{k}={v}");
        }
    }
    Ok(())
}

// ---- proxy stop / start / patch ---------------------------------------------------------

/// Every row of `state/vms` that may still run a VM with VPC egress: its
/// egress is not `internet` and it is not terminated (a row past its wall
/// counts too: the registry may lag the service), and every row file that
/// cannot be read. Named by file stem; no AWS call.
fn vpc_vms(paths: &Paths) -> Result<Vec<String>> {
    let dir = paths.vms();
    let entries = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(CliError::Msg(format!("cannot list {}: {e}", dir.display()))),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".toml")).filter(|s| !s.starts_with('.')) else { continue };
        match read_regular_file(&dir.join(&name)) {
            Ok(None) => {}
            Ok(Some(text)) => match toml::from_str::<VmRow>(&text) {
                Ok(row) if row.egress == "internet" || row.status == RowStatus::Terminated => {}
                Ok(_) => out.push(stem.to_string()),
                Err(_) => out.push(format!("{stem} (unreadable)")),
            },
            Err(_) => out.push(format!("{stem} (unreadable)")),
        }
    }
    out.sort();
    Ok(out)
}

/// A registry row of a live VM with VPC egress (not terminated, its wall
/// not passed; a pending row counts): its stem, the first one found. While
/// one runs, the connector must have ENIs.
fn live_vpc_vm(paths: &Paths) -> std::result::Result<Option<String>, String> {
    let now = crate::wire::time::unix_now();
    let rows = list_rows(paths).map_err(|e| format!("state/vms: {e}"))?;
    Ok(rows.into_iter().find(|r| r.egress == "vpc" && r.status != RowStatus::Terminated && r.wall_left(now).is_none_or(|l| l > 0)).map(|r| r.stem()))
}

fn proxy_stop(yes: bool) -> Result<()> {
    let ctx = Ctx::load()?;
    let instance = ctx.instance()?;
    let vms = vpc_vms(&ctx.paths)?;
    if !vms.is_empty() && !yes {
        return Err(CliError::Policy(format!(
            "proxy stop: {} row(s) of state/vms may still run a VM with VPC egress, which would lose every egress: {}; terminate them (ai-env vm terminate ID, ai-env vm gc --yes) or pass --yes",
            vms.len(),
            vms.join(", ")
        )));
    }
    ctx.operator("proxy stop")?;
    live_proxy("proxy stop", instance)?;
    let now = ops::stop_instance(instance).map_err(aws("proxy stop"))?;
    audit(&ctx.paths, "proxy_stop", &[("instance", instance.to_string()), ("vpc_vms", vms.len().to_string())]);
    note(&format!("proxy {instance}: {now}; waiting for stopped"));
    wait_state(instance, "stopped", ctx.wait(Wait::INSTANCE)).map_err(aws("proxy stop"))?;
    say(&format!("proxy {instance}: stopped; vpc VMs have no egress until `ai-env proxy start`"));
    Ok(())
}

/// Wait until `instance` is in `want` (`running`, `stopped`).
fn wait_state(instance: &str, want: &str, wait: Wait) -> std::result::Result<(), String> {
    let mut last = String::new();
    for n in 0..wait.tries.max(1) {
        if n > 0 {
            std::thread::sleep(wait.step);
        }
        let state = ops::instance_state(instance)?;
        if state == want {
            return Ok(());
        }
        if matches!(state.as_str(), "shutting-down" | "terminated") {
            return Err(format!("{instance} is {state}"));
        }
        last = state;
    }
    Err(format!("{instance} is not {want} after {} s (last state {last})", wait.budget().as_secs()))
}

/// Wait until the SSM agent of `instance` reports Online.
fn wait_online(instance: &str, wait: Wait) -> std::result::Result<(), String> {
    let mut last = String::from("not registered");
    for n in 0..wait.tries.max(1) {
        if n > 0 {
            std::thread::sleep(wait.step);
        }
        match ops::ssm_ping(instance)? {
            Some(p) if p == "Online" => return Ok(()),
            Some(p) => last = p,
            None => {}
        }
    }
    Err(format!("the SSM agent of {instance} is not Online after {} s ({last})", wait.budget().as_secs()))
}

/// A `--status` line and its pairs.
type StatusLine = (String, BTreeMap<String, String>);

/// One `ai-env-proxy-reload --status` run: its line and pairs, `None` when
/// it printed none (it could not fetch the parameters).
fn status_line(ctx: &Ctx, instance: &str, comment: &str) -> std::result::Result<Option<StatusLine>, String> {
    let inv = ops::run_shell(instance, &[&format!("{RELOAD} --status")], comment, STATUS_EXEC_S, ctx.wait(Wait::STATUS))?;
    let Some(line) = split_status_output(&inv.stdout).1 else { return Ok(None) };
    let pairs = parse_reload_status(line)?;
    Ok(Some((line.to_string(), pairs)))
}

/// squid serves the current parameters: active, they parse, and they are
/// the set it was last configured with.
fn serving(st: &BTreeMap<String, String>) -> bool {
    let get = |k: &str| st.get(k).map(String::as_str);
    get("squid") == Some("active") && get("parse") == Some("ok") && get("applied") == Some("yes")
}

/// Wait until `--status` says squid serves the current parameters: the
/// status line. SSM refusing the command right after a start
/// (`InvalidInstanceId`) and a status run that printed nothing are retried.
fn wait_serving(ctx: &Ctx, instance: &str, wait: Wait) -> std::result::Result<String, String> {
    let mut last = String::new();
    for n in 0..wait.tries.max(1) {
        if n > 0 {
            std::thread::sleep(wait.step);
        }
        match status_line(ctx, instance, "ai-env proxy start") {
            Ok(Some((line, pairs))) if serving(&pairs) => return Ok(line),
            Ok(Some((line, _))) => last = line,
            Ok(None) => last = "no status line (the parameters could not be fetched)".into(),
            Err(e) if e.contains("InvalidInstanceId") => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(format!("squid does not serve the current parameters after {} s ({last}); a reload refused at boot leaves it stopped (fail closed): ai-env egress status", wait.budget().as_secs()))
}

fn proxy_start() -> Result<()> {
    let ctx = Ctx::load()?;
    let instance = ctx.instance()?;
    ctx.operator("proxy start")?;
    live_proxy("proxy start", instance)?;
    let now = ops::start_instance(instance).map_err(aws("proxy start"))?;
    audit(&ctx.paths, "proxy_start", &[("instance", instance.to_string())]);
    note(&format!("proxy {instance}: {now}; waiting for running, SSM Online, then squid"));
    wait_state(instance, "running", ctx.wait(Wait::INSTANCE)).map_err(aws("proxy start"))?;
    wait_online(instance, ctx.wait(Wait::SSM_ONLINE)).map_err(aws("proxy start"))?;
    let line = wait_serving(&ctx, instance, ctx.wait(Wait::SQUID)).map_err(aws("proxy start"))?;
    say(&format!("proxy {instance}: running, SSM Online"));
    say(&line);
    Ok(())
}

/// The patch: AL2023 locks dnf to the release of the instance's AMI
/// (deterministic upgrades; the stack never replaces the proxy for a newer
/// AMI), so `--security` alone sees no newer package: `--releasever=latest`
/// takes the security updates of the newest release. The release package
/// and squid are printed before and after; squid restarts only when the
/// upgrade succeeded.
const PATCH_SCRIPT: [&str; 5] = [
    "set -e",
    r#"echo "before: $(rpm -q system-release) $(rpm -q squid)""#,
    "dnf -y upgrade --security --releasever=latest",
    r#"echo "after: $(rpm -q system-release) $(rpm -q squid)""#,
    "systemctl restart squid",
];

fn proxy_patch() -> Result<()> {
    let ctx = Ctx::load()?;
    let instance = ctx.instance()?;
    ctx.operator("proxy patch")?;
    let state = live_proxy("proxy patch", instance)?;
    if state != "running" {
        return Err(CliError::Aws(format!("proxy patch: the proxy {instance} is {state}: `ai-env proxy start` first")));
    }
    note(&format!("patching {instance} through SSM: dnf -y upgrade --security --releasever=latest, then systemctl restart squid"));
    let inv: Invocation = ops::run_shell(instance, &PATCH_SCRIPT, "ai-env proxy patch", PATCH_EXEC_S, ctx.wait(Wait::PATCH)).map_err(aws("proxy patch"))?;
    let ok = inv.succeeded();
    audit(&ctx.paths, "proxy_patch", &[("instance", instance.to_string()), ("result", if ok { "ok".to_string() } else { format!("{} exit {}", inv.status, inv.code) })]);
    let marked = |m: &str| inv.stdout.lines().map(str::trim).find_map(|l| l.strip_prefix(m)).map(str::to_string);
    let (before, after) = (marked("before: "), marked("after: "));
    if let Some(b) = &before {
        say(&format!("before: {b}"));
    }
    if !ok {
        return Err(CliError::Aws(format!("proxy patch: the patch ended {} (exit {}): {}", inv.status, inv.code, inv.last_line())));
    }
    match (&before, &after) {
        (Some(b), Some(a)) => say(&format!("after:  {a}{}", if a == b { " (the release and squid unchanged)" } else { "" })),
        _ => say(&format!("patched {instance} (no before/after line: {})", inv.last_line())),
    }
    match status_line(&ctx, instance, "ai-env proxy patch").map_err(aws("proxy patch"))? {
        Some((line, pairs)) => {
            say(&line);
            if !serving(&pairs) {
                return Err(CliError::Aws(format!("proxy patch: squid does not serve the current parameters after the restart ({line}): ai-env egress status")));
            }
            Ok(())
        }
        None => Err(CliError::Aws("proxy patch: `ai-env-proxy-reload --status` printed no line after the restart (the parameters could not be fetched): ai-env egress status".into())),
    }
}

// ---- egress status ----------------------------------------------------------------------

/// One check's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Ok,
    Drift,
    /// Not verified (a call failed, an answer was incomplete): exit 7 unless something drifted.
    Unknown,
    /// Not checked because the proxy is stopped: shown as unknown, never a failure.
    Skipped,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Drift => "DRIFT",
            Verdict::Unknown | Verdict::Skipped => "unknown",
        }
    }
}

type Judged = (Verdict, String);

fn ok(detail: impl Into<String>) -> Judged {
    (Verdict::Ok, detail.into())
}

fn unknown(detail: impl Into<String>) -> Judged {
    (Verdict::Unknown, detail.into())
}

/// `Ok(detail)` when `problems` is empty, else drift naming them all.
fn verdict(problems: &[String], detail: impl Into<String>) -> Judged {
    if problems.is_empty() {
        ok(detail)
    } else {
        (Verdict::Drift, problems.join("; "))
    }
}

struct Row {
    check: &'static str,
    verdict: Verdict,
    detail: String,
}

#[derive(Default)]
struct Report {
    rows: Vec<Row>,
    /// The facts of the `get-network-connector` answer the `connector` row
    /// judged ok (what `egress check` binds a pass to); `None` otherwise.
    connector_facts: Option<super::ConnectorFacts>,
}

impl Report {
    fn push(&mut self, check: &'static str, (verdict, detail): Judged) {
        self.rows.push(Row { check, verdict, detail });
    }

    /// `judge` over the answer, or unknown with the call's error.
    fn call<T>(&mut self, check: &'static str, r: std::result::Result<T, String>, judge: impl FnOnce(T) -> Judged) {
        match r {
            Ok(v) => self.push(check, judge(v)),
            Err(e) => self.push(check, unknown(e)),
        }
    }

    fn named(&self, f: impl Fn(Verdict) -> bool) -> Vec<&'static str> {
        self.rows.iter().filter(|r| f(r.verdict)).map(|r| r.check).collect()
    }
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
}

fn list(v: &[String]) -> String {
    format!("[{}]", v.join(", "))
}

/// The connector: ACTIVE, its last update successful (or none), and its
/// VPC egress configuration exactly the stack's VM subnet and security
/// group, IPv4, `[MicroVm]`.
fn judge_connector(doc: &Value, configured: &str, recorded: Option<&str>, subnet: &str, vm_sg: &str) -> Judged {
    let mut p = Vec::new();
    let reason = |code: &str, why: &str| {
        let r = [text(doc, code), text(doc, why)].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(": ");
        if r.is_empty() {
            String::new()
        } else {
            format!(" ({r})")
        }
    };
    let state = text(doc, "State");
    if state != "ACTIVE" {
        p.push(format!("State {}{}", if state.is_empty() { "?" } else { state }, reason("StateReasonCode", "StateReason")));
    }
    match text(doc, "LastUpdateStatus") {
        "" | "Successful" => {}
        s => p.push(format!("LastUpdateStatus {s}{}", reason("LastUpdateStatusReasonCode", "LastUpdateStatusReason"))),
    }
    let arn = text(doc, "Arn");
    if normalize_connector(arn) != normalize_connector(configured) {
        p.push(format!("Arn {arn:?} is not [aws].egress_connector_arn {configured}"));
    }
    if let Some(r) = recorded.filter(|r| normalize_connector(r) != normalize_connector(configured)) {
        p.push(format!("state/infra.toml records connector_arn {r}: {HINT}"));
    }
    match doc.get("Configuration").and_then(|c| c.get("VpcEgressConfiguration")) {
        None => p.push("no Configuration.VpcEgressConfiguration".into()),
        Some(c) => {
            for (key, want) in [("SubnetIds", vec![subnet.to_string()]), ("SecurityGroupIds", vec![vm_sg.to_string()]), ("AssociatedComputeResourceTypes", vec!["MicroVm".to_string()])] {
                let got = strs(c.get(key));
                if got != want {
                    p.push(format!("{key} {}, not exactly {}", list(&got), list(&want)));
                }
            }
            if text(c, "NetworkProtocol") != "IPv4" {
                p.push(format!("NetworkProtocol {:?}, not IPv4", text(c, "NetworkProtocol")));
            }
        }
    }
    verdict(&p, format!("ACTIVE, {subnet}, {vm_sg}, IPv4, [MicroVm]"))
}

/// The ENIs in the VM subnet (the connector's): each exactly in the VM
/// security group, without IPv6 or a public address, whenever there are
/// any. None at all is drift only while a registry row says a vpc VM runs
/// (`live_vm`) with the connector ACTIVE: the ENIs may exist only while one
/// runs (unmeasured; T5.1 measures it), so an idle stack's empty subnet is
/// skipped, never drift.
fn judge_enis(doc: &Value, vm_sg: &str, connector_active: bool, live_vm: &std::result::Result<Option<String>, String>) -> Judged {
    let listed = doc.get("NetworkInterfaces").and_then(Value::as_array);
    let enis = listed.map_or(&[][..], Vec::as_slice);
    if enis.is_empty() {
        let why = if listed.is_none() { "the answer lists no NetworkInterfaces" } else { "no ENI in the VM subnet" };
        return match (connector_active, live_vm) {
            (false, _) => unknown(format!("{why} (the connector is not ACTIVE)")),
            (true, Ok(Some(vm))) => (Verdict::Drift, format!("{why}, but the connector is ACTIVE and the vpc VM {vm} runs")),
            (true, Ok(None)) if listed.is_some() => (Verdict::Skipped, "no connector ENI (they may exist only while a vpc VM runs; T5.1 measures it)".into()),
            (true, Ok(None)) => unknown(why),
            (true, Err(e)) => unknown(format!("{why}; whether a vpc VM runs is unknown ({e})")),
        };
    }
    let mut p = Vec::new();
    let mut ips = Vec::new();
    for e in enis {
        let id = text(e, "NetworkInterfaceId");
        let mut groups: Vec<String> = arr(e, "Groups").iter().map(|g| text(g, "GroupId").to_string()).collect();
        groups.sort();
        if groups != [vm_sg] {
            p.push(format!("{id} has groups {}, not exactly [{vm_sg}]", list(&groups)));
        }
        if !arr(e, "Ipv6Addresses").is_empty() {
            p.push(format!("{id} has IPv6 addresses"));
        }
        if let Some(public) = e.get("Association").map(|a| text(a, "PublicIp")).filter(|ip| !ip.is_empty()) {
            p.push(format!("{id} has the public address {public}"));
        }
        let mut own: Vec<&str> = arr(e, "PrivateIpAddresses").iter().map(|a| text(a, "PrivateIpAddress")).filter(|ip| !ip.is_empty()).collect();
        if own.is_empty() && !text(e, "PrivateIpAddress").is_empty() {
            own.push(text(e, "PrivateIpAddress"));
        }
        ips.extend(own.into_iter().map(str::to_string));
    }
    verdict(&p, format!("{} ENI(s), {}, groups [{vm_sg}]", enis.len(), ips.join(", ")))
}

/// Every field a route can send traffic to.
const ROUTE_TARGETS: [&str; 10] =
    ["GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId", "InstanceId", "EgressOnlyInternetGatewayId", "LocalGatewayId", "CarrierGatewayId", "CoreNetworkArn"];

/// Where a route goes (every target field set, joined).
fn route_target(r: &Value) -> String {
    let t: Vec<&str> = ROUTE_TARGETS.iter().map(|k| text(r, k)).filter(|t| !t.is_empty()).collect();
    if t.is_empty() {
        "?".to_string()
    } else {
        t.join("+")
    }
}

fn route_destination(r: &Value) -> String {
    ["DestinationCidrBlock", "DestinationIpv6CidrBlock", "DestinationPrefixListId"].iter().map(|k| text(r, k)).filter(|t| !t.is_empty()).collect::<Vec<_>>().join("+")
}

/// A `local` route of the VPC: its only target is `local` and its only
/// destination one of the VPC's IPv4 CIDRs.
fn is_local_route(r: &Value, cidrs: &[String]) -> bool {
    let targets: Vec<&str> = ROUTE_TARGETS.iter().map(|k| text(r, k)).filter(|t| !t.is_empty()).collect();
    targets == ["local"] && text(r, "DestinationIpv6CidrBlock").is_empty() && text(r, "DestinationPrefixListId").is_empty() && cidrs.iter().any(|c| c == text(r, "DestinationCidrBlock"))
}

/// The IPv4 CIDRs of the VPC (its primary block and every associated one).
fn vpc_cidrs(doc: &Value, vpc: &str) -> Vec<String> {
    let Some(v) = arr(doc, "Vpcs").iter().find(|v| text(v, "VpcId") == vpc) else { return Vec::new() };
    let mut out: Vec<String> = std::iter::once(text(v, "CidrBlock"))
        .chain(arr(v, "CidrBlockAssociationSet").iter().filter(|a| a.get("CidrBlockState").is_none_or(|s| text(s, "State") == "associated")).map(|a| text(a, "CidrBlock")))
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The VM subnet's effective route table (its explicit association, else
/// the VPC's main table) has `local` routes of the VPC's CIDRs only and no
/// route propagation.
fn judge_route_table(doc: &Value, subnet: &str, cidrs: &[String]) -> Judged {
    let tables = arr(doc, "RouteTables");
    let associated = |t: &Value, pick: &dyn Fn(&Value) -> bool| arr(t, "Associations").iter().any(|a| pick(a) && a.get("AssociationState").is_none_or(|s| text(s, "State") == "associated"));
    let explicit = tables.iter().find(|t| associated(t, &|a| text(a, "SubnetId") == subnet));
    let (table, how) = match explicit {
        Some(t) => (t, "explicit"),
        None => match tables.iter().find(|t| associated(t, &|a| a.get("Main").and_then(Value::as_bool) == Some(true))) {
            Some(t) => (t, "the VPC's main table"),
            None => return (Verdict::Drift, format!("no route table of the VPC applies to {subnet}")),
        },
    };
    let id = text(table, "RouteTableId");
    let routes = arr(table, "Routes");
    let mut p: Vec<String> = routes.iter().filter(|r| !is_local_route(r, cidrs)).map(|r| format!("{id} ({how}) routes {} → {}", route_destination(r), route_target(r))).collect();
    if !arr(table, "PropagatingVgws").is_empty() {
        p.push(format!("{id} ({how}) propagates routes from a virtual private gateway"));
    }
    verdict(&p, format!("{id} ({how}): local only ({})", routes.iter().map(route_destination).collect::<Vec<_>>().join(", ")))
}

/// A security group's permissions, one string per (protocol, port, peer):
/// `tcp 3128 sg:sg-…`, `udp 53 cidr:1.1.1.1/32`, `all all cidr6:::/0`.
fn flat_rules(perms: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for perm in perms {
        let proto = match text(perm, "IpProtocol") {
            "-1" => "all",
            p => p,
        };
        let port = match (perm.get("FromPort").and_then(Value::as_i64), perm.get("ToPort").and_then(Value::as_i64)) {
            (Some(a), Some(b)) if a == b => a.to_string(),
            (Some(a), Some(b)) if a >= 0 => format!("{a}-{b}"),
            _ => "all".to_string(),
        };
        let mut peers: Vec<String> = Vec::new();
        peers.extend(arr(perm, "IpRanges").iter().map(|r| format!("cidr:{}", text(r, "CidrIp"))));
        peers.extend(arr(perm, "Ipv6Ranges").iter().map(|r| format!("cidr6:{}", text(r, "CidrIpv6"))));
        peers.extend(arr(perm, "PrefixListIds").iter().map(|r| format!("pl:{}", text(r, "PrefixListId"))));
        peers.extend(arr(perm, "UserIdGroupPairs").iter().map(|r| format!("sg:{}", text(r, "GroupId"))));
        if peers.is_empty() {
            peers.push("no-peer".into());
        }
        out.extend(peers.into_iter().map(|peer| format!("{proto} {port} {peer}")));
    }
    out.sort();
    out
}

/// `direction: unexpected …; missing …` when `got` is not exactly `want`.
fn rule_diff(direction: &str, got: &[String], want: &[String]) -> Option<String> {
    let mut want = want.to_vec();
    want.sort();
    if got == want.as_slice() {
        return None;
    }
    let extra: Vec<&str> = got.iter().filter(|g| !want.contains(g)).map(String::as_str).collect();
    let missing: Vec<&str> = want.iter().filter(|w| !got.contains(w)).map(String::as_str).collect();
    let mut parts = Vec::new();
    if !extra.is_empty() {
        parts.push(format!("unexpected {}", extra.join(", ")));
    }
    if !missing.is_empty() {
        parts.push(format!("missing {}", missing.join(", ")));
    }
    if parts.is_empty() {
        parts.push(format!("a rule twice ({})", got.join(", ")));
    }
    Some(format!("{direction}: {}", parts.join("; ")))
}

/// A network ACL's entries, one string per entry but the default deny
/// (rule 32767): `egress allow tcp 3128 cidr:10.42.0.10/32`.
fn flat_acl_entries(entries: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = entries
        .iter()
        .filter(|e| !(e.get("RuleNumber").and_then(Value::as_i64) == Some(32767) && text(e, "RuleAction") == "deny"))
        .map(|e| {
            let direction = if e.get("Egress").and_then(Value::as_bool) == Some(true) { "egress" } else { "ingress" };
            let proto = match text(e, "Protocol") {
                "6" | "tcp" => "tcp",
                "17" | "udp" => "udp",
                "-1" | "all" => "all",
                other => other,
            };
            let port = match e.get("PortRange").map(|p| (p.get("From").and_then(Value::as_i64), p.get("To").and_then(Value::as_i64))) {
                Some((Some(a), Some(b))) if a == b => a.to_string(),
                Some((Some(a), Some(b))) => format!("{a}-{b}"),
                _ => "all".to_string(),
            };
            let peer = match (text(e, "CidrBlock"), text(e, "Ipv6CidrBlock")) {
                (c, _) if !c.is_empty() => format!("cidr:{c}"),
                (_, c6) => format!("cidr6:{c6}"),
            };
            format!("{direction} {} {proto} {port} {peer}", text(e, "RuleAction"))
        })
        .collect();
    out.sort();
    out
}

/// The VM subnet's own network ACL (never the VPC's default one, which
/// allows everything): TCP 3128 out to the proxy, the return traffic in
/// from it, the default deny, nothing else.
fn judge_nacl(doc: &Value, subnet: &str, proxy_ip: &str) -> Judged {
    let acls = arr(doc, "NetworkAcls");
    let Some(acl) = acls.iter().find(|a| arr(a, "Associations").iter().any(|s| text(s, "SubnetId") == subnet)) else {
        return (Verdict::Drift, format!("no network ACL is associated with {subnet}"));
    };
    let id = text(acl, "NetworkAclId");
    if acl.get("IsDefault").and_then(Value::as_bool) != Some(false) {
        return (Verdict::Drift, format!("{subnet} uses the VPC's default network ACL {id} (it allows everything), not its own"));
    }
    let want = [format!("egress allow tcp 3128 cidr:{proxy_ip}/32"), format!("ingress allow tcp 1024-65535 cidr:{proxy_ip}/32")];
    let p: Vec<String> = rule_diff(id, &flat_acl_entries(arr(acl, "Entries")), &want).into_iter().collect();
    verdict(&p, format!("{id}: egress tcp 3128 to {proxy_ip}/32, ingress tcp 1024-65535 from {proxy_ip}/32, default deny"))
}

/// The proxy's egress: TCP 443 anywhere, UDP and TCP 53 to each resolver.
fn proxy_egress_rules() -> Vec<String> {
    let mut want = vec!["tcp 443 cidr:0.0.0.0/0".to_string()];
    for r in RESOLVERS {
        for proto in ["udp", "tcp"] {
            want.push(format!("{proto} 53 cidr:{r}/32"));
        }
    }
    want
}

/// The VM security group (no ingress; egress exactly TCP 3128 to the
/// proxy's address — an address, not the proxy SG: any interface holding
/// that group would be a second, unfiltered proxy), the proxy's and the
/// VPC's default one, exactly as designed.
fn judge_security_groups(doc: &Value, vm_sg: &str, proxy_sg: &str, proxy_ip: &str) -> Vec<(&'static str, Judged)> {
    let groups = arr(doc, "SecurityGroups");
    let judge = |found: Option<&Value>, what: String, ingress: Vec<String>, egress: Vec<String>, detail: String| -> Judged {
        let Some(g) = found else { return (Verdict::Drift, format!("{what} is not a security group of the VPC")) };
        let p: Vec<String> = [rule_diff("ingress", &flat_rules(arr(g, "IpPermissions")), &ingress), rule_diff("egress", &flat_rules(arr(g, "IpPermissionsEgress")), &egress)].into_iter().flatten().collect();
        verdict(&p, detail)
    };
    let by_id = |id: &str| groups.iter().find(|g| text(g, "GroupId") == id);
    vec![
        ("vm-sg", judge(by_id(vm_sg), vm_sg.to_string(), vec![], vec![format!("tcp 3128 cidr:{proxy_ip}/32")], format!("{vm_sg}: no ingress; egress tcp 3128 → {proxy_ip}/32 only"))),
        (
            "proxy-sg",
            judge(
                by_id(proxy_sg),
                proxy_sg.to_string(),
                vec![format!("tcp 3128 sg:{vm_sg}")],
                proxy_egress_rules(),
                format!("{proxy_sg}: ingress tcp 3128 from {vm_sg}; egress tcp 443 0.0.0.0/0, udp+tcp 53 to {}", RESOLVERS.join(", ")),
            ),
        ),
        ("default-sg", judge(groups.iter().find(|g| text(g, "GroupName") == "default"), "the default group".into(), vec![], vec![], "no rules".into())),
    ]
}

/// The VPC: no IPv6 block. Also its DHCP option set id (`Err`: the AWS
/// default or none, which is drift of the DHCP row).
fn judge_vpc(doc: &Value, vpc: &str) -> (Judged, std::result::Result<String, String>) {
    let Some(v) = arr(doc, "Vpcs").iter().find(|v| text(v, "VpcId") == vpc) else {
        return ((Verdict::Drift, format!("{vpc} not found")), Err(format!("{vpc} not found")));
    };
    let ipv6: Vec<&str> = arr(v, "Ipv6CidrBlockAssociationSet")
        .iter()
        .filter(|a| !matches!(a.get("Ipv6CidrBlockState").map(|s| text(s, "State")), Some("disassociated" | "failed")))
        .map(|a| text(a, "Ipv6CidrBlock"))
        .collect();
    let p: Vec<String> = if ipv6.is_empty() { vec![] } else { vec![format!("IPv6 blocks {}", ipv6.join(", "))] };
    let dhcp = match text(v, "DhcpOptionsId") {
        "" | "default" => Err(format!("{vpc} uses the default DHCP options (AmazonProvidedDNS), not exactly {}", RESOLVERS.join(", "))),
        id => Ok(id.to_string()),
    };
    (verdict(&p, format!("{vpc} {}, no IPv6", text(v, "CidrBlock"))), dhcp)
}

/// DNS attributes for `dns_mode`: `none` → DNS support off; `firewall` →
/// on; hostnames always off.
fn judge_dns(support: Option<bool>, hostnames: Option<bool>, mode: &str) -> Judged {
    let want = match mode {
        "none" => false,
        "firewall" => true,
        other => return (Verdict::Drift, format!("state/infra.toml dns_mode {other:?} is neither none nor firewall")),
    };
    let show = |b: Option<bool>| b.map_or_else(|| "unknown".to_string(), |b| b.to_string());
    let mut p = Vec::new();
    if support != Some(want) {
        p.push(format!("enableDnsSupport {} (dnsMode {mode} wants {want})", show(support)));
    }
    if hostnames != Some(false) {
        p.push(format!("enableDnsHostnames {} (wants false)", show(hostnames)));
    }
    verdict(&p, format!("enableDnsSupport {want}, enableDnsHostnames false (dnsMode {mode})"))
}

/// `dnsMode` firewall: the VPC's resolver must answer no name. Exactly one
/// rule group is associated, COMPLETE; it holds exactly one rule — BLOCK
/// (NXDOMAIN or NODATA) over a domain list that is exactly `*`, no query
/// type restriction, no threat-protection rule — and the firewall fails
/// closed (`FirewallFailOpen` DISABLED). `rules_of` and `domains_of` fetch
/// a rule group's rules and a domain list's domains.
fn judge_firewall(
    assocs: &Value,
    config: &Value,
    rules_of: impl Fn(&str) -> std::result::Result<Value, String>,
    domains_of: impl Fn(&str) -> std::result::Result<Value, String>,
) -> std::result::Result<Judged, String> {
    let mut p = Vec::new();
    let fail_open = config.get("FirewallConfig").map(|c| text(c, "FirewallFailOpen")).unwrap_or("");
    if fail_open != "DISABLED" {
        p.push(format!("FirewallFailOpen {}, not DISABLED (an unreachable firewall would let every name resolve)", if fail_open.is_empty() { "unset" } else { fail_open }));
    }
    match arr(assocs, "FirewallRuleGroupAssociations") {
        [] => p.push("no DNS Firewall rule group is associated with the VPC: its resolver answers every name".into()),
        [a] => {
            if text(a, "Status") != "COMPLETE" {
                p.push(format!("the association {} is {}, not COMPLETE", text(a, "Id"), text(a, "Status")));
            }
            let rules_doc = rules_of(text(a, "FirewallRuleGroupId"))?;
            match arr(&rules_doc, "FirewallRules") {
                [rule] => {
                    if text(rule, "Action") != "BLOCK" {
                        p.push(format!("the rule's action is {:?}, not BLOCK", text(rule, "Action")));
                    }
                    if !matches!(text(rule, "BlockResponse"), "NXDOMAIN" | "NODATA") {
                        p.push(format!("the rule answers {:?}, not NXDOMAIN or NODATA", text(rule, "BlockResponse")));
                    }
                    if !text(rule, "Qtype").is_empty() {
                        p.push(format!("the rule blocks only query type {}", text(rule, "Qtype")));
                    }
                    if !text(rule, "FirewallThreatProtectionId").is_empty() {
                        p.push("the rule is a threat-protection rule, not a domain list".into());
                    }
                    match text(rule, "FirewallDomainListId") {
                        "" => p.push("the rule has no domain list".into()),
                        list_id => {
                            let domains = strs(domains_of(list_id)?.get("Domains"));
                            if !(domains == ["*"] || domains == ["*."]) {
                                p.push(format!("its domain list {list_id} holds {} domain(s), not exactly *", domains.len()));
                            }
                        }
                    }
                }
                rules => p.push(format!("the rule group holds {} rules, not exactly one BLOCK rule (another may allow names first)", rules.len())),
            }
        }
        many => p.push(format!(
            "{} rule groups are associated ({}): another may allow names before the block",
            many.len(),
            many.iter().map(|a| text(a, "FirewallRuleGroupId")).collect::<Vec<_>>().join(", ")
        )),
    }
    Ok(verdict(&p, "one rule group: BLOCK * (no query type), fail-open DISABLED"))
}

fn check_firewall(vpc: &str) -> std::result::Result<Judged, String> {
    let assocs = ops::firewall_associations(vpc)?;
    let config = ops::firewall_config(vpc)?;
    judge_firewall(&assocs, &config, ops::firewall_rules, ops::firewall_domains)
}

/// The DHCP option set's `domain-name-servers` are exactly [`RESOLVERS`].
fn judge_dhcp(doc: &Value, id: &str) -> Judged {
    let Some(set) = arr(doc, "DhcpOptions").iter().find(|d| text(d, "DhcpOptionsId") == id) else {
        return (Verdict::Drift, format!("{id} not found"));
    };
    let servers: Vec<String> = arr(set, "DhcpConfigurations").iter().filter(|c| text(c, "Key") == "domain-name-servers").flat_map(|c| arr(c, "Values")).map(|v| text(v, "Value").to_string()).collect();
    let mut got = servers.clone();
    got.sort();
    let mut want: Vec<String> = RESOLVERS.iter().map(|r| (*r).to_string()).collect();
    want.sort();
    if got == want {
        ok(format!("{id}: domain-name-servers {}", servers.join(", ")))
    } else {
        (Verdict::Drift, format!("{id}: domain-name-servers {}, not exactly {}", list(&servers), list(&want)))
    }
}

/// None of `items` may exist (states in `gone` are history, not resources).
fn judge_none(items: &[Value], describe: impl Fn(&Value) -> (String, String), gone: &[&str], what: &str) -> Judged {
    let live: Vec<String> = items
        .iter()
        .map(&describe)
        .filter(|(_, state)| !gone.contains(&state.to_ascii_lowercase().as_str()))
        .map(|(name, state)| format!("{name} ({state})"))
        .collect();
    if live.is_empty() {
        ok(format!("no {what}"))
    } else {
        (Verdict::Drift, format!("{what}: {}", live.join(", ")))
    }
}

fn judge_endpoints(doc: &Value) -> Judged {
    judge_none(arr(doc, "VpcEndpoints"), |e| (format!("{} {}", text(e, "VpcEndpointId"), text(e, "ServiceName")), text(e, "State").to_string()), &["deleted", "rejected", "failed", "expired"], "VPC endpoints")
}

fn judge_nat(doc: &Value) -> Judged {
    judge_none(arr(doc, "NatGateways"), |n| (text(n, "NatGatewayId").to_string(), text(n, "State").to_string()), &["deleted", "failed"], "NAT gateways")
}

fn judge_peering(doc: &Value, vpc: &str) -> Judged {
    let mine: Vec<Value> = arr(doc, "VpcPeeringConnections")
        .iter()
        .filter(|c| ["RequesterVpcInfo", "AccepterVpcInfo"].iter().any(|side| c.get(side).is_some_and(|i| text(i, "VpcId") == vpc)))
        .cloned()
        .collect();
    judge_none(&mine, |c| (text(c, "VpcPeeringConnectionId").to_string(), c.get("Status").map(|s| text(s, "Code")).unwrap_or("").to_string()), &["deleted", "rejected", "failed", "expired"], "peering connections")
}

/// The proxy instance: its state (stopped is a legitimate, closed state),
/// exactly the proxy security group, the stack's proxy address (which a set
/// `[aws].proxy_private_ip`, what the VMs are told, must equal). The state
/// is returned.
fn judge_instance(inst: &Value, proxy_sg: &str, proxy_ip: &str, configured_ip: Option<&str>) -> (Judged, String) {
    let state = inst.get("State").map(|s| text(s, "Name")).unwrap_or("").to_string();
    let mut groups: Vec<String> = arr(inst, "SecurityGroups").iter().map(|g| text(g, "GroupId").to_string()).collect();
    groups.sort();
    let mut p = Vec::new();
    if groups != [proxy_sg] {
        p.push(format!("security groups {}, not exactly [{proxy_sg}]", list(&groups)));
    }
    let ip = text(inst, "PrivateIpAddress");
    if ip != proxy_ip {
        p.push(format!("private address {ip:?}, not {proxy_ip}"));
    }
    if let Some(c) = configured_ip.map(str::trim).filter(|c| !c.is_empty() && *c != proxy_ip) {
        p.push(format!("[aws].proxy_private_ip {c} is not the stack's {proxy_ip}: {HINT}"));
    }
    let judged = match state.as_str() {
        "running" => verdict(&p, format!("running, {proxy_ip}, [{proxy_sg}]")),
        "stopped" => verdict(&p, "stopped: vpc VMs have no egress until `ai-env proxy start`"),
        "shutting-down" | "terminated" => (Verdict::Drift, format!("{state}: {}", proxy_gone(text(inst, "InstanceId")))),
        other => unknown(format!("{other} (retry once it runs or has stopped)")),
    };
    (judged, state)
}

/// The `rpm -q squid` line and the `--status` line of the status command's output.
fn split_status_output(out: &str) -> (Option<&str>, Option<&str>) {
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    (lines.iter().find(|l| !l.starts_with("squid=")).copied(), lines.iter().rev().find(|l| l.starts_with("squid=")).copied())
}

fn judge_rpm(rpm: Option<&str>) -> Judged {
    match rpm {
        Some(v) if v.starts_with("squid-") => ok(v),
        Some(other) => (Verdict::Drift, format!("rpm -q squid: {other}")),
        None => (Verdict::Drift, "rpm -q squid printed nothing".into()),
    }
}

/// squid active, the current parameters parse, and they are what squid
/// was last configured with (`applied=yes`).
fn judge_proxy_config(st: &BTreeMap<String, String>) -> Judged {
    let get = |k: &str| st.get(k).map(String::as_str);
    let mut p = Vec::new();
    if get("squid") != Some("active") {
        p.push(format!("squid is {} on the proxy", get("squid").unwrap_or("unknown")));
    }
    if get("parse") != Some("ok") {
        p.push("the current parameters fail `squid -k parse`: the next reload will be refused (correct them, then ai-env egress reload)".into());
    }
    match get("applied") {
        Some("yes") => {}
        Some("no") => p.push("the proxy serves an older config: ai-env egress reload".into()),
        _ => p.push("the status line has no applied=yes|no (an ai-env-proxy-reload older than contract 4: make deploy)".into()),
    }
    let counts = ["allowed", "extras", "suspended"].iter().map(|k| format!("{k}={}", get(k).unwrap_or("?"))).collect::<Vec<_>>().join(" ");
    verdict(&p, format!("squid active, parse ok, applied yes ({counts})"))
}

/// The four parameters exist and parse; with a status line, each
/// `sha256_<param>` the proxy printed (64 hex digits) equals the hash of
/// the value SSM holds.
fn judge_parameters(st: Option<&BTreeMap<String, String>>, values: &BTreeMap<String, Param>, missing: &[String]) -> Judged {
    let mut p = Vec::new();
    if !missing.is_empty() {
        p.push(format!("missing {}", missing.join(", ")));
    }
    for param in PARAMS {
        let Some(v) = values.get(&param_name(param)).map(|v| v.value.as_str()) else {
            if missing.is_empty() {
                p.push(format!("{} not in the answer", param_name(param)));
            }
            continue;
        };
        let grammar = match param {
            "allow" | "suspended" => parse_hosts(v).err(),
            "extras" => parse_extras(v).err(),
            _ => None,
        };
        if let Some(e) = grammar {
            p.push(format!("{param}: {e}"));
        }
        if !fits_parameter(v) {
            p.push(format!("{param}: {} bytes, over {PARAM_MAX_BYTES}", v.len()));
        }
        if let Some(st) = st {
            let want = value_sha256(v);
            match st.get(&format!("sha256_{param}")) {
                Some(got) if !is_sha256_hex(got) => p.push(format!("{param}: the status line's sha256_{param} is not 64 hex digits")),
                Some(got) if *got == want => {}
                Some(got) => p.push(format!("{param}: the proxy reads sha256 {}…, SSM holds {}… (another prefix, or a write in between: retry)", &got[..12], &want[..12])),
                None => p.push(format!("{param}: the status line has no sha256_{param}")),
            }
        }
    }
    let how = if st.is_some() { "hashes equal to the proxy's" } else { "hashes not compared: the proxy does not run" };
    verdict(&p, format!("{} parameters under {PARAMETER_PREFIX}, valid, {how}", PARAMS.len()))
}

/// `squid.conf` and `allow` as SSM holds them are what the stack rendered
/// (`squid_conf_sha256`, `allow_sha256` of `state/infra.toml`); without
/// those hashes the content cannot be verified.
fn judge_stack_params(values: &BTreeMap<String, Param>, state: &InfraState) -> Judged {
    let mut p = Vec::new();
    let mut unverified = Vec::new();
    for (param, field, want) in [("squid.conf", "squid_conf_sha256", state.squid_conf_sha256.as_deref()), ("allow", "allow_sha256", state.allow_sha256.as_deref())] {
        let want = want.map(|w| w.trim().to_ascii_lowercase()).filter(|w| is_sha256_hex(w));
        match (want, values.get(&param_name(param))) {
            (None, _) => unverified.push(format!("state/infra.toml has no valid {field}")),
            (Some(_), None) => unverified.push(format!("{} could not be read", param_name(param))),
            (Some(w), Some(v)) if value_sha256(&v.value) == w => {}
            (Some(_), Some(_)) => p.push(format!("{param} differs from what the stack rendered ({} was changed outside `make deploy`)", param_name(param))),
        }
    }
    if !p.is_empty() {
        return (Verdict::Drift, p.into_iter().chain(unverified).collect::<Vec<_>>().join("; "));
    }
    if !unverified.is_empty() {
        return unknown(format!("{}: {HINT}", unverified.join("; ")));
    }
    ok("squid.conf and allow are what the stack rendered")
}

/// One row of the network verification, for `ai-env egress check`: the check, its status (`ok` | `DRIFT` | `unknown`; a stopped proxy's skipped checks are `unknown`) and the detail.
pub(crate) struct NetworkRow {
    pub check: &'static str,
    pub status: &'static str,
    pub detail: String,
}

/// Every check of `ai-env egress status` (the operator-account check first, the same calls, no output), for `ai-env egress check`, which requires every row `ok`; and the facts of the connector answer the `connector` row judged ok, which a pass is bound to (the configuration verified, not a later read).
pub(crate) fn network_verification() -> Result<(Vec<NetworkRow>, Option<super::ConnectorFacts>)> {
    let ctx = Ctx::load()?;
    let (_, r) = verify(&ctx, "egress check")?;
    let facts = r.connector_facts;
    Ok((r.rows.into_iter().map(|row| NetworkRow { check: row.check, status: row.verdict.label(), detail: row.detail }).collect(), facts))
}

fn status(json: bool) -> Result<()> {
    let ctx = Ctx::load()?;
    let (instance, r) = verify(&ctx, "egress status")?;
    let instance = instance.as_str();
    let drift = r.named(|v| v == Verdict::Drift);
    let unverified = r.named(|v| v == Verdict::Unknown);
    if json {
        let rows: Vec<Value> = r.rows.iter().map(|row| serde_json::json!({ "check": row.check, "status": row.verdict.label().to_ascii_lowercase(), "detail": row.detail })).collect();
        let doc = serde_json::json!({
            "connector": ctx.connector, "proxy_instance": instance, "ok": drift.is_empty() && unverified.is_empty(), "drift": drift,
            "unknown": r.named(|v| matches!(v, Verdict::Unknown | Verdict::Skipped)), "unverified": unverified, "rows": rows
        });
        say(&serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        for row in &r.rows {
            say(&format!("{:<7}  {:<15} {}", row.verdict.label(), row.check, row.detail));
        }
    }
    if !drift.is_empty() {
        return Err(CliError::Msg(format!("egress status: drift in {}", drift.join(", "))));
    }
    if !unverified.is_empty() {
        return Err(CliError::Aws(format!("egress status: {} could not be verified (see the rows)", unverified.join(", "))));
    }
    Ok(())
}

/// The checks of `egress status` (`what` names the command in the operator-account refusal): the proxy instance id and the rows.
fn verify(ctx: &Ctx, what: &str) -> Result<(String, Report)> {
    let vpc = ctx.need("egress_vpc_id", &ctx.state.egress_vpc_id, "vpc-")?;
    let subnet = ctx.need("vm_subnet_id", &ctx.state.vm_subnet_id, "subnet-")?;
    let vm_sg = ctx.need("vm_egress_security_group_id", &ctx.state.vm_egress_security_group_id, "sg-")?;
    let proxy_sg = ctx.need("proxy_security_group_id", &ctx.state.proxy_security_group_id, "sg-")?;
    let instance = ctx.instance()?;
    let dns_mode = ctx.need("dns_mode", &ctx.state.dns_mode, "")?;
    ctx.check_prefix()?;
    // The stack's proxy address: the VM SG and the VM subnet's NACL name it.
    let proxy_addr = ctx.need("proxy_private_ip", &ctx.state.proxy_private_ip, "")?;
    if !is_rfc1918(proxy_addr) {
        return Err(CliError::Msg(format!("{} proxy_private_ip = {proxy_addr:?} is not an RFC 1918 address: {HINT}", ctx.paths.infra_state().display())));
    }
    ctx.operator(what)?;

    let mut r = Report::default();
    let connector = ops::get_connector(&ctx.connector);
    let active = connector.as_ref().is_ok_and(|d| text(d, "State") == "ACTIVE");
    match connector {
        Ok(doc) => {
            let judged = judge_connector(&doc, &ctx.connector, ctx.state.connector_arn.as_deref(), subnet, vm_sg);
            if judged.0 == Verdict::Ok {
                r.connector_facts = super::ConnectorFacts::from_get(&doc);
            }
            r.push("connector", judged);
        }
        Err(e) => r.push("connector", unknown(e)),
    }
    let live_vm = live_vpc_vm(&ctx.paths);
    r.call("connector-enis", ops::subnet_enis(subnet), |doc| judge_enis(&doc, vm_sg, active, &live_vm));
    let vpc_doc = ops::vpc(vpc);
    let cidrs = vpc_doc.as_ref().ok().map(|d| vpc_cidrs(d, vpc)).filter(|c| !c.is_empty());
    r.call("vm-route-table", ops::route_tables(vpc), |doc| match &cidrs {
        Some(c) => judge_route_table(&doc, subnet, c),
        None => unknown("the VPC's CIDRs could not be read"),
    });
    r.call("vm-nacl", ops::subnet_network_acls(subnet), |doc| judge_nacl(&doc, subnet, proxy_addr));
    match ops::security_groups(vpc) {
        Ok(doc) => {
            for (check, judged) in judge_security_groups(&doc, vm_sg, proxy_sg, proxy_addr) {
                r.push(check, judged);
            }
        }
        Err(e) => {
            for check in ["vm-sg", "proxy-sg", "default-sg"] {
                r.push(check, unknown(e.clone()));
            }
        }
    }
    let dhcp = match vpc_doc {
        Ok(doc) => {
            let (judged, dhcp) = judge_vpc(&doc, vpc);
            r.push("vpc", judged);
            Some(dhcp)
        }
        Err(e) => {
            r.push("vpc", unknown(e));
            None
        }
    };
    match ops::vpc_attribute(vpc, "enableDnsSupport").and_then(|s| ops::vpc_attribute(vpc, "enableDnsHostnames").map(|h| (s, h))) {
        Ok((support, hostnames)) => r.push("vpc-dns", judge_dns(support, hostnames, dns_mode)),
        Err(e) => r.push("vpc-dns", unknown(e)),
    }
    if dns_mode == "firewall" {
        r.call("dns-firewall", check_firewall(vpc), |judged| judged);
    }
    match dhcp {
        Some(Ok(id)) => r.call("dhcp-options", ops::dhcp_options(&id), |doc| judge_dhcp(&doc, &id)),
        Some(Err(why)) => r.push("dhcp-options", (Verdict::Drift, why)),
        None => r.push("dhcp-options", unknown("the VPC could not be read")),
    }
    r.call("vpc-endpoints", ops::vpc_endpoints(vpc), |doc| judge_endpoints(&doc));
    r.call("vpc-peering", ops::peering_connections(), |doc| judge_peering(&doc, vpc));
    r.call("nat-gateways", ops::nat_gateways(vpc), |doc| judge_nat(&doc));
    let state = match ops::instance(instance) {
        Ok(doc) => {
            let (judged, state) = judge_instance(&doc, proxy_sg, proxy_addr, ctx.cfg.aws.proxy_private_ip.as_deref());
            r.push("proxy-instance", judged);
            Some(state)
        }
        Err(e) if e.contains("InvalidInstanceID.NotFound") => {
            r.push("proxy-instance", (Verdict::Drift, proxy_gone(instance)));
            Some("gone".to_string())
        }
        Err(e) => {
            r.push("proxy-instance", unknown(e));
            None
        }
    };
    let names: Vec<String> = PARAMS.iter().map(|p| param_name(p)).collect();
    let params = ops::get_parameters(&names);
    if state.as_deref() == Some("running") {
        let online = match ops::ssm_ping(instance) {
            Ok(Some(p)) if p == "Online" => {
                r.push("proxy-ssm", ok("Online"));
                true
            }
            Ok(Some(p)) => {
                r.push("proxy-ssm", (Verdict::Drift, format!("PingStatus {p}: SSM cannot reach the proxy (reload, patch and status need it)")));
                false
            }
            Ok(None) => {
                r.push("proxy-ssm", (Verdict::Drift, format!("{instance} is not registered with SSM")));
                false
            }
            Err(e) => {
                r.push("proxy-ssm", unknown(e));
                false
            }
        };
        if online {
            match ops::run_shell(instance, &["rpm -q squid || true", &format!("{RELOAD} --status")], "ai-env egress status", STATUS_EXEC_S, ctx.wait(Wait::STATUS)) {
                Ok(inv) => {
                    let (rpm, line) = split_status_output(&inv.stdout);
                    r.push("squid-rpm", judge_rpm(rpm));
                    match line.map(parse_reload_status) {
                        Some(Ok(st)) => {
                            r.push("proxy-config", judge_proxy_config(&st));
                            r.call("parameters", params.clone(), |(values, missing)| judge_parameters(Some(&st), &values, &missing));
                        }
                        Some(Err(e)) => {
                            r.push("proxy-config", unknown(e));
                            r.push("parameters", unknown("no status line to compare with"));
                        }
                        None => {
                            r.push("proxy-config", unknown(format!("`ai-env-proxy-reload --status` printed no status line (exit {}: {}): the proxy could not fetch its parameters", inv.code, inv.last_line())));
                            r.push("parameters", unknown("no status line to compare with"));
                        }
                    }
                }
                Err(e) => {
                    for check in ["squid-rpm", "proxy-config", "parameters"] {
                        r.push(check, unknown(e.clone()));
                    }
                }
            }
        } else {
            for check in ["squid-rpm", "proxy-config", "parameters"] {
                r.push(check, unknown("SSM cannot reach the proxy"));
            }
        }
    } else {
        // A stopped proxy serves nothing: its checks are skipped, not failed. Any other state is not verifiable now.
        let (v, why) = match state.as_deref() {
            Some("stopped") => (Verdict::Skipped, "the proxy is stopped: not checked".to_string()),
            Some(s) => (Verdict::Unknown, format!("the proxy is {s}")),
            None => (Verdict::Unknown, "the proxy's state is unknown".to_string()),
        };
        for check in ["proxy-ssm", "squid-rpm", "proxy-config"] {
            r.push(check, (v, why.clone()));
        }
        r.call("parameters", params.clone(), |(values, missing)| judge_parameters(None, &values, &missing));
    }
    r.call("stack-params", params, |(values, _)| judge_stack_params(&values, &ctx.state));
    Ok((instance.to_string(), r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::egress::PROXY_IP;
    use serde_json::json;

    const SUBNET: &str = "subnet-0aaa1111bbbb2222c";
    const VM_SG: &str = "sg-0ddd3333eeee4444f";
    const PROXY_SG: &str = "sg-0fff5555aaaa6666b";
    const CONN: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    fn golden() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/egress/lambda-core.get-network-connector.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn the_connector_must_be_active_updated_and_exactly_the_stack_config() {
        let doc = golden();
        assert_eq!(judge_connector(&doc, CONN, Some(&format!("{CONN}:1")), SUBNET, VM_SG).0, Verdict::Ok);
        let mut pending = doc.clone();
        pending["State"] = json!("PENDING");
        pending["StateReason"] = json!("creating ENIs");
        let (v, d) = judge_connector(&pending, CONN, None, SUBNET, VM_SG);
        assert_eq!(v, Verdict::Drift);
        assert!(d.contains("State PENDING (creating ENIs)"), "{d}");
        let mut updating = doc.clone();
        updating["LastUpdateStatus"] = json!("InProgress");
        assert!(judge_connector(&updating, CONN, None, SUBNET, VM_SG).1.contains("LastUpdateStatus InProgress"));
        let mut no_update = doc.clone();
        no_update.as_object_mut().unwrap().remove("LastUpdateStatus");
        assert_eq!(judge_connector(&no_update, CONN, None, SUBNET, VM_SG).0, Verdict::Ok, "never updated");
        let mut extra = doc.clone();
        extra["Configuration"]["VpcEgressConfiguration"]["SecurityGroupIds"] = json!([VM_SG, "sg-0123456789abcdef0"]);
        assert!(judge_connector(&extra, CONN, None, SUBNET, VM_SG).1.contains("SecurityGroupIds"));
        assert!(judge_connector(&doc, CONN, None, "subnet-0123456789abcdef0", VM_SG).1.contains("SubnetIds"));
        assert!(judge_connector(&doc, "arn:aws:lambda:eu-central-1:123456789012:network-connector:other", None, SUBNET, VM_SG).1.contains("is not [aws].egress_connector_arn"));
        assert!(judge_connector(&doc, CONN, Some("arn:aws:lambda:eu-central-1:123456789012:network-connector:old"), SUBNET, VM_SG).1.contains("make infra-status WRITE=1"));
        let mut v6 = doc;
        v6["Configuration"]["VpcEgressConfiguration"]["NetworkProtocol"] = json!("DualStack");
        assert!(judge_connector(&v6, CONN, None, SUBNET, VM_SG).1.contains("NetworkProtocol"));
    }

    #[test]
    fn the_effective_route_table_must_be_local_only() {
        let cidrs = vec!["10.42.0.0/16".to_string()];
        let local = json!({"DestinationCidrBlock": "10.42.0.0/16", "GatewayId": "local", "Origin": "CreateRouteTable", "State": "active"});
        let main_local = json!({"RouteTableId": "rtb-0000000000000000a", "Associations": [{"Main": true, "RouteTableId": "rtb-0000000000000000a"}], "Routes": [local], "PropagatingVgws": []});
        let mut main = main_local.clone();
        main["Routes"].as_array_mut().unwrap().push(json!({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0123"}));
        let vms = json!({"RouteTableId": "rtb-0000000000000000b", "Associations": [{"Main": false, "SubnetId": SUBNET, "AssociationState": {"State": "associated"}}], "Routes": [local], "PropagatingVgws": []});
        let (v, d) = judge_route_table(&json!({"RouteTables": [main.clone(), vms.clone()]}), SUBNET, &cidrs);
        assert_eq!(v, Verdict::Ok, "{d}");
        assert!(d.contains("rtb-0000000000000000b (explicit)"));
        // Without its explicit association the subnet falls back to the main table: fine when local only, drift when it routes out.
        let (v, d) = judge_route_table(&json!({"RouteTables": [main_local]}), SUBNET, &cidrs);
        assert!(v == Verdict::Ok && d.contains("main table"), "{d}");
        let (v, d) = judge_route_table(&json!({"RouteTables": [main]}), SUBNET, &cidrs);
        assert_eq!(v, Verdict::Drift);
        assert!(d.contains("main table") && d.contains("0.0.0.0/0 → igw-0123"), "{d}");
        let with = |route: Value| {
            let mut t = vms.clone();
            t["Routes"].as_array_mut().unwrap().push(route);
            judge_route_table(&json!({"RouteTables": [t]}), SUBNET, &cidrs)
        };
        assert!(with(json!({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0abc"})).1.contains("0.0.0.0/0 → nat-0abc"));
        assert!(with(json!({"DestinationCidrBlock": "10.43.0.0/16", "GatewayId": "local"})).1.contains("10.43.0.0/16 → local"), "local, but not a VPC CIDR");
        assert!(with(json!({"DestinationCidrBlock": "10.42.0.0/16", "GatewayId": "local", "NetworkInterfaceId": "eni-0abc"})).1.contains("local+eni-0abc"), "a local route sent to an ENI");
        assert!(with(json!({"DestinationIpv6CidrBlock": "::/0", "GatewayId": "local"})).1.contains("::/0 → local"));
        let mut vgw = vms;
        vgw["PropagatingVgws"] = json!([{"GatewayId": "vgw-0123"}]);
        let (v, d) = judge_route_table(&json!({"RouteTables": [vgw]}), SUBNET, &cidrs);
        assert!(v == Verdict::Drift && d.contains("virtual private gateway"), "{d}");
        assert_eq!(judge_route_table(&json!({"RouteTables": []}), SUBNET, &cidrs).0, Verdict::Drift);
        let vpc = json!({"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.42.0.0/16", "CidrBlockAssociationSet": [{"CidrBlock": "10.42.0.0/16", "CidrBlockState": {"State": "associated"}}, {"CidrBlock": "10.99.0.0/16", "CidrBlockState": {"State": "disassociated"}}]}]});
        assert_eq!(vpc_cidrs(&vpc, "vpc-1"), cidrs);
    }

    fn sg(id: &str, name: &str, ingress: Value, egress: Value) -> Value {
        json!({"GroupId": id, "GroupName": name, "IpPermissions": ingress, "IpPermissionsEgress": egress})
    }

    fn green_sgs() -> Value {
        let pair = |g: &str| json!([{"GroupId": g, "UserId": "123456789012"}]);
        json!({"SecurityGroups": [
            sg(VM_SG, "ai-env-vm-egress", json!([]), json!([{"IpProtocol": "tcp", "FromPort": 3128, "ToPort": 3128, "UserIdGroupPairs": [], "IpRanges": [{"CidrIp": "10.42.0.10/32"}], "Ipv6Ranges": [], "PrefixListIds": []}])),
            sg(PROXY_SG, "ai-env-proxy", json!([{"IpProtocol": "tcp", "FromPort": 3128, "ToPort": 3128, "UserIdGroupPairs": pair(VM_SG), "IpRanges": []}]), json!([
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "udp", "FromPort": 53, "ToPort": 53, "IpRanges": [{"CidrIp": "1.1.1.1/32"}, {"CidrIp": "9.9.9.9/32"}]},
                {"IpProtocol": "tcp", "FromPort": 53, "ToPort": 53, "IpRanges": [{"CidrIp": "9.9.9.9/32"}, {"CidrIp": "1.1.1.1/32"}]}
            ])),
            sg("sg-0bbb7777cccc8888d", "default", json!([]), json!([]))
        ]})
    }

    #[test]
    fn security_groups_are_exactly_as_designed() {
        let doc = green_sgs();
        for (check, (v, d)) in judge_security_groups(&doc, VM_SG, PROXY_SG, PROXY_IP) {
            assert_eq!(v, Verdict::Ok, "{check}: {d}");
        }
        let flip = |f: &dyn Fn(&mut Value)| {
            let mut d = green_sgs();
            f(&mut d);
            judge_security_groups(&d, VM_SG, PROXY_SG, PROXY_IP).into_iter().filter(|(_, (v, _))| *v == Verdict::Drift).map(|(c, (_, d))| format!("{c}: {d}")).collect::<Vec<_>>()
        };
        let cidr = flip(&|d| d["SecurityGroups"][0]["IpPermissionsEgress"][0]["IpRanges"] = json!([{"CidrIp": "10.42.0.10/32"}, {"CidrIp": "0.0.0.0/0"}]));
        assert_eq!(cidr.len(), 1);
        assert!(cidr[0].starts_with("vm-sg: egress: unexpected tcp 3128 cidr:0.0.0.0/0"), "{cidr:?}");
        // The proxy SG as the target (the design before the W1 review): any interface holding it would be a second proxy.
        let by_group = flip(&|d| {
            d["SecurityGroups"][0]["IpPermissionsEgress"][0]["IpRanges"] = json!([]);
            d["SecurityGroups"][0]["IpPermissionsEgress"][0]["UserIdGroupPairs"] = json!([{"GroupId": PROXY_SG}]);
        });
        assert!(by_group[0].contains(&format!("unexpected tcp 3128 sg:{PROXY_SG}; missing tcp 3128 cidr:10.42.0.10/32")), "{by_group:?}");
        let pl = flip(&|d| d["SecurityGroups"][0]["IpPermissionsEgress"][0]["PrefixListIds"] = json!([{"PrefixListId": "pl-6ea54007"}]));
        assert!(pl[0].contains("unexpected tcp 3128 pl:pl-6ea54007"), "{pl:?}");
        let extra = flip(&|d| d["SecurityGroups"][0]["IpPermissionsEgress"].as_array_mut().unwrap().push(json!({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})));
        assert!(extra[0].contains("unexpected all all cidr:0.0.0.0/0"), "{extra:?}");
        let ingress = flip(&|d| d["SecurityGroups"][0]["IpPermissions"] = json!([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]));
        assert!(ingress[0].contains("ingress: unexpected tcp 22 cidr:10.0.0.0/8"), "{ingress:?}");
        let v6 = flip(&|d| d["SecurityGroups"][1]["IpPermissionsEgress"][0]["Ipv6Ranges"] = json!([{"CidrIpv6": "::/0"}]));
        assert!(v6[0].starts_with("proxy-sg: egress: unexpected tcp 443 cidr6:::/0"), "{v6:?}");
        let resolver = flip(&|d| d["SecurityGroups"][1]["IpPermissionsEgress"][1]["IpRanges"] = json!([{"CidrIp": "1.1.1.1/32"}]));
        assert!(resolver[0].contains("missing udp 53 cidr:9.9.9.9/32"), "{resolver:?}");
        let default = flip(&|d| d["SecurityGroups"][2]["IpPermissions"] = json!([{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-0bbb7777cccc8888d"}]}]));
        assert!(default[0].starts_with("default-sg: ingress: unexpected all all sg:sg-0bbb7777cccc8888d"), "{default:?}");
        let gone = flip(&|d| d["SecurityGroups"].as_array_mut().unwrap().remove(1).as_object().map(|_| ()).unwrap());
        assert!(gone[0].contains("is not a security group of the VPC"), "{gone:?}");
    }

    #[test]
    fn enis_vpc_dns_dhcp_and_absent_resources() {
        let eni = |groups: Value| json!({"NetworkInterfaces": [{"NetworkInterfaceId": "eni-01", "Groups": groups, "PrivateIpAddresses": [{"PrivateIpAddress": "10.42.1.17", "Primary": true}], "Ipv6Addresses": []}]});
        let (idle, running): (std::result::Result<Option<String>, String>, _) = (Ok(None), Ok(Some("microvm-1".to_string())));
        let (v, d) = judge_enis(&eni(json!([{"GroupId": VM_SG}])), VM_SG, true, &idle);
        assert_eq!(v, Verdict::Ok);
        assert!(d.contains("10.42.1.17"), "{d}");
        assert_eq!(judge_enis(&eni(json!([{"GroupId": VM_SG}, {"GroupId": PROXY_SG}])), VM_SG, true, &idle).0, Verdict::Drift, "groups are strict whenever ENIs exist");
        let none = json!({"NetworkInterfaces": []});
        let (v, d) = judge_enis(&none, VM_SG, true, &running);
        assert!(v == Verdict::Drift && d.contains("the vpc VM microvm-1 runs"), "{d}");
        let (v, d) = judge_enis(&none, VM_SG, true, &idle);
        assert!(v == Verdict::Skipped && d.contains("T5.1"), "an idle stack is never drift: {d}");
        assert_eq!(judge_enis(&none, VM_SG, true, &Err("state/vms: unreadable".into())).0, Verdict::Unknown);
        assert_eq!(judge_enis(&json!({}), VM_SG, true, &running).0, Verdict::Drift);
        assert_eq!(judge_enis(&json!({}), VM_SG, true, &idle).0, Verdict::Unknown, "a malformed answer never passes");
        assert_eq!(judge_enis(&none, VM_SG, false, &running).0, Verdict::Unknown);
        let vpc = json!({"Vpcs": [{"VpcId": "vpc-0123456789abcdef0", "CidrBlock": "10.42.0.0/16", "DhcpOptionsId": "dopt-0123456789abcdef0", "Ipv6CidrBlockAssociationSet": []}]});
        let ((v, _), dhcp) = judge_vpc(&vpc, "vpc-0123456789abcdef0");
        assert_eq!((v, dhcp), (Verdict::Ok, Ok("dopt-0123456789abcdef0".to_string())));
        let mut v6 = vpc.clone();
        v6["Vpcs"][0]["Ipv6CidrBlockAssociationSet"] = json!([{"Ipv6CidrBlock": "2a05:d014::/56", "Ipv6CidrBlockState": {"State": "associated"}}]);
        v6["Vpcs"][0]["DhcpOptionsId"] = json!("default");
        let ((v, d), dhcp) = judge_vpc(&v6, "vpc-0123456789abcdef0");
        assert!(v == Verdict::Drift && d.contains("2a05:d014::/56") && dhcp.is_err(), "{d}");
        assert_eq!(judge_dns(Some(false), Some(false), "none").0, Verdict::Ok);
        assert!(judge_dns(Some(true), Some(false), "none").1.contains("enableDnsSupport true (dnsMode none wants false)"));
        assert_eq!(judge_dns(Some(true), Some(false), "firewall").0, Verdict::Ok);
        assert_eq!(judge_dns(Some(true), Some(true), "firewall").0, Verdict::Drift);
        assert_eq!(judge_dns(None, Some(false), "none").0, Verdict::Drift);
        assert_eq!(judge_dns(Some(false), Some(false), "both").0, Verdict::Drift);
        let dhcp = |servers: Value| json!({"DhcpOptions": [{"DhcpOptionsId": "dopt-1", "DhcpConfigurations": [{"Key": "domain-name-servers", "Values": servers}]}]});
        assert_eq!(judge_dhcp(&dhcp(json!([{"Value": "1.1.1.1"}, {"Value": "9.9.9.9"}])), "dopt-1").0, Verdict::Ok);
        assert_eq!(judge_dhcp(&dhcp(json!([{"Value": "AmazonProvidedDNS"}])), "dopt-1").0, Verdict::Drift);
        assert_eq!(judge_dhcp(&dhcp(json!([{"Value": "1.1.1.1"}, {"Value": "9.9.9.9"}, {"Value": "8.8.8.8"}])), "dopt-1").0, Verdict::Drift);
        assert_eq!(judge_endpoints(&json!({"VpcEndpoints": [{"VpcEndpointId": "vpce-1", "ServiceName": "com.amazonaws.eu-central-1.s3", "State": "deleted"}]})).0, Verdict::Ok);
        assert!(judge_endpoints(&json!({"VpcEndpoints": [{"VpcEndpointId": "vpce-1", "ServiceName": "com.amazonaws.eu-central-1.s3", "State": "available"}]})).1.contains("vpce-1 com.amazonaws.eu-central-1.s3 (available)"));
        assert_eq!(judge_nat(&json!({"NatGateways": [{"NatGatewayId": "nat-1", "State": "available"}]})).0, Verdict::Drift);
        let peer = json!({"VpcPeeringConnections": [{"VpcPeeringConnectionId": "pcx-1", "AccepterVpcInfo": {"VpcId": "vpc-0123456789abcdef0"}, "RequesterVpcInfo": {"VpcId": "vpc-9"}, "Status": {"Code": "active"}}, {"VpcPeeringConnectionId": "pcx-2", "AccepterVpcInfo": {"VpcId": "vpc-7"}, "RequesterVpcInfo": {"VpcId": "vpc-8"}, "Status": {"Code": "active"}}]});
        let (v, d) = judge_peering(&peer, "vpc-0123456789abcdef0");
        assert!(v == Verdict::Drift && d.contains("pcx-1 (active)") && !d.contains("pcx-2"), "{d}");
        assert_eq!(judge_peering(&peer, "vpc-0000000000000000f").0, Verdict::Ok);
    }

    #[test]
    fn the_instance_rows() {
        let inst = |state: &str| json!({"InstanceId": "i-0123456789abcdef0", "State": {"Name": state}, "PrivateIpAddress": PROXY_IP, "SecurityGroups": [{"GroupId": PROXY_SG}]});
        assert_eq!(judge_instance(&inst("running"), PROXY_SG, PROXY_IP, Some(PROXY_IP)).0 .0, Verdict::Ok);
        let ((v, d), state) = judge_instance(&inst("stopped"), PROXY_SG, PROXY_IP, None);
        assert!(v == Verdict::Ok && state == "stopped" && d.contains("ai-env proxy start"), "{d}");
        let ((v, d), _) = judge_instance(&inst("terminated"), PROXY_SG, PROXY_IP, None);
        assert!(v == Verdict::Drift && d.contains("names a proxy that no longer exists (i-0123456789abcdef0)") && d.contains("make infra-status WRITE=1") && !d.contains("make deploy"), "{d}");
        assert_eq!(judge_instance(&inst("pending"), PROXY_SG, PROXY_IP, None).0 .0, Verdict::Unknown);
        assert_eq!(judge_instance(&inst("stopping"), PROXY_SG, PROXY_IP, None).0 .0, Verdict::Unknown, "still serving");
        let mut widened = inst("running");
        widened["SecurityGroups"].as_array_mut().unwrap().push(json!({"GroupId": "sg-0123456789abcdef0"}));
        assert_eq!(judge_instance(&widened, PROXY_SG, PROXY_IP, None).0 .0, Verdict::Drift);
        assert_eq!(judge_instance(&inst("running"), PROXY_SG, "10.42.0.11", None).0 .0, Verdict::Drift);
        assert!(judge_instance(&inst("running"), PROXY_SG, PROXY_IP, Some("10.42.0.99")).0 .1.contains("[aws].proxy_private_ip 10.42.0.99"));
    }

    fn green_nacl() -> Value {
        let entry = |n: i64, egress: bool, proto: &str, action: &str, cidr: &str, ports: Option<(i64, i64)>| {
            let mut e = json!({"RuleNumber": n, "Egress": egress, "Protocol": proto, "RuleAction": action, "CidrBlock": cidr});
            if let Some((a, b)) = ports {
                e["PortRange"] = json!({"From": a, "To": b});
            }
            e
        };
        json!({"NetworkAcls": [{"NetworkAclId": "acl-0123456789abcdef0", "IsDefault": false, "VpcId": "vpc-0123456789abcdef0",
            "Associations": [{"NetworkAclAssociationId": "aclassoc-01", "NetworkAclId": "acl-0123456789abcdef0", "SubnetId": SUBNET}],
            "Entries": [
                entry(100, true, "6", "allow", "10.42.0.10/32", Some((3128, 3128))),
                entry(32767, true, "-1", "deny", "0.0.0.0/0", None),
                entry(100, false, "6", "allow", "10.42.0.10/32", Some((1024, 65535))),
                entry(32767, false, "-1", "deny", "0.0.0.0/0", None)
            ]}]})
    }

    #[test]
    fn the_vm_subnet_has_its_own_nacl_with_exactly_the_proxy_path() {
        let (v, d) = judge_nacl(&green_nacl(), SUBNET, PROXY_IP);
        assert_eq!(v, Verdict::Ok, "{d}");
        let flip = |f: &dyn Fn(&mut Value)| {
            let mut d = green_nacl();
            f(&mut d);
            judge_nacl(&d, SUBNET, PROXY_IP)
        };
        let (v, d) = flip(&|d| d["NetworkAcls"][0]["IsDefault"] = json!(true));
        assert!(v == Verdict::Drift && d.contains("default network ACL"), "{d}");
        let (v, d) = flip(&|d| d["NetworkAcls"][0]["Entries"].as_array_mut().unwrap().push(json!({"RuleNumber": 90, "Egress": true, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"})));
        assert!(v == Verdict::Drift && d.contains("unexpected egress allow all all cidr:0.0.0.0/0"), "{d}");
        let (_, d) = flip(&|d| d["NetworkAcls"][0]["Entries"][2]["PortRange"] = json!({"From": 0, "To": 65535}));
        assert!(d.contains("unexpected ingress allow tcp 0-65535") && d.contains("missing ingress allow tcp 1024-65535"), "{d}");
        let (_, d) = flip(&|d| d["NetworkAcls"][0]["Entries"].as_array_mut().unwrap().push(json!({"RuleNumber": 110, "Egress": true, "Protocol": "6", "RuleAction": "allow", "Ipv6CidrBlock": "::/0", "PortRange": {"From": 443, "To": 443}})));
        assert!(d.contains("unexpected egress allow tcp 443 cidr6:::/0"), "{d}");
        let (_, d) = flip(&|d| d["NetworkAcls"][0]["Entries"].as_array_mut().unwrap().remove(0).as_object().map(|_| ()).unwrap());
        assert!(d.contains("missing egress allow tcp 3128 cidr:10.42.0.10/32"), "{d}");
        assert_eq!(judge_nacl(&json!({"NetworkAcls": []}), SUBNET, PROXY_IP).0, Verdict::Drift);
    }

    fn firewall(assocs: Value, config: Value, rules: Value, domains: Value) -> Judged {
        judge_firewall(&assocs, &config, |g| if g == "rslvr-frg-1" { Ok(rules.clone()) } else { Err(format!("unexpected group {g}")) }, |l| if l == "rslvr-fdl-1" { Ok(domains.clone()) } else { Err(format!("unexpected list {l}")) })
            .unwrap()
    }

    #[test]
    fn the_dns_firewall_blocks_every_name_and_fails_closed() {
        let assoc = json!({"FirewallRuleGroupAssociations": [{"Id": "rslvr-frgassoc-1", "FirewallRuleGroupId": "rslvr-frg-1", "VpcId": "vpc-1", "Priority": 101, "Status": "COMPLETE"}]});
        let config = json!({"FirewallConfig": {"Id": "rslvr-fc-1", "ResourceId": "vpc-1", "FirewallFailOpen": "DISABLED"}});
        let rule = json!({"FirewallRuleGroupId": "rslvr-frg-1", "FirewallDomainListId": "rslvr-fdl-1", "Name": "ai-env-egress-block-all", "Priority": 100, "Action": "BLOCK", "BlockResponse": "NXDOMAIN"});
        let rules = json!({"FirewallRules": [rule.clone()]});
        let all = json!({"Domains": ["*"]});
        assert_eq!(firewall(assoc.clone(), config.clone(), rules.clone(), all.clone()).0, Verdict::Ok);
        assert_eq!(firewall(assoc.clone(), config.clone(), rules.clone(), json!({"Domains": ["*."]})).0, Verdict::Ok);
        let drift = |j: Judged, what: &str| assert!(j.0 == Verdict::Drift && j.1.contains(what), "{what}: {j:?}");
        drift(firewall(assoc.clone(), json!({"FirewallConfig": {"FirewallFailOpen": "ENABLED"}}), rules.clone(), all.clone()), "FirewallFailOpen ENABLED");
        drift(firewall(json!({"FirewallRuleGroupAssociations": []}), config.clone(), rules.clone(), all.clone()), "no DNS Firewall rule group");
        let mut two = assoc.clone();
        two["FirewallRuleGroupAssociations"].as_array_mut().unwrap().push(json!({"Id": "rslvr-frgassoc-2", "FirewallRuleGroupId": "rslvr-frg-2", "Status": "COMPLETE"}));
        drift(firewall(two, config.clone(), rules.clone(), all.clone()), "2 rule groups are associated");
        let mut updating = assoc.clone();
        updating["FirewallRuleGroupAssociations"][0]["Status"] = json!("UPDATING");
        drift(firewall(updating, config.clone(), rules.clone(), all.clone()), "UPDATING, not COMPLETE");
        let with = |k: &str, v: Value| {
            let mut r = rule.clone();
            r[k] = v;
            json!({"FirewallRules": [r]})
        };
        drift(firewall(assoc.clone(), config.clone(), with("Action", json!("ALLOW")), all.clone()), "not BLOCK");
        drift(firewall(assoc.clone(), config.clone(), with("Qtype", json!("A")), all.clone()), "query type A");
        drift(firewall(assoc.clone(), config.clone(), with("BlockResponse", json!("OVERRIDE")), all.clone()), "not NXDOMAIN or NODATA");
        drift(firewall(assoc.clone(), config.clone(), json!({"FirewallRules": [with("Priority", json!(50))["FirewallRules"][0].clone(), rule.clone()]}), all.clone()), "holds 2 rules");
        drift(firewall(assoc.clone(), config.clone(), rules.clone(), json!({"Domains": ["example.com."]})), "not exactly *");
        drift(firewall(assoc.clone(), config, rules, json!({"Domains": ["*", "example.com."]})), "2 domain(s)");
    }

    fn param(v: &str) -> Param {
        Param { value: v.to_string(), version: 1 }
    }

    fn values() -> BTreeMap<String, Param> {
        [("squid.conf", "http_port 10.42.0.10:3128\n"), ("allow", "api.anthropic.com\n"), ("extras", super::super::EXTRAS_HEADER), ("suspended", super::super::SUSPENDED_HEADER)].iter().map(|(p, v)| (param_name(p), param(v))).collect()
    }

    fn status_of(values: &BTreeMap<String, Param>, applied: &str) -> String {
        let sums: Vec<String> = PARAMS.iter().map(|p| format!("sha256_{p}={}", value_sha256(&values[&param_name(p)].value))).collect();
        format!("squid=active allowed=1 extras=0 suspended=0 {} parse=ok{applied}", sums.join(" "))
    }

    #[test]
    fn the_status_line_against_the_parameters() {
        let vals = values();
        let line = status_of(&vals, " applied=yes");
        let out = format!("squid-6.13-1.amzn2023.0.1.aarch64\n{line}\n");
        let (rpm, l) = split_status_output(&out);
        assert_eq!((rpm, l), (Some("squid-6.13-1.amzn2023.0.1.aarch64"), Some(line.as_str())));
        assert_eq!(judge_rpm(rpm).0, Verdict::Ok);
        assert_eq!(judge_rpm(Some("package squid is not installed")).0, Verdict::Drift);
        let st = parse_reload_status(&line).unwrap();
        assert_eq!(judge_proxy_config(&st).0, Verdict::Ok);
        assert!(serving(&st));
        assert_eq!(judge_parameters(Some(&st), &vals, &[]).0, Verdict::Ok);
        let old = parse_reload_status(&status_of(&vals, " applied=no")).unwrap();
        assert!(judge_proxy_config(&old).1.contains("the proxy serves an older config: ai-env egress reload"));
        assert!(!serving(&old));
        let none = parse_reload_status(&status_of(&vals, "")).unwrap();
        assert_eq!(judge_proxy_config(&none).0, Verdict::Drift, "no applied= is not a pass");
        let inactive = parse_reload_status(&status_of(&vals, " applied=yes").replace("squid=active", "squid=inactive").replace("parse=ok", "parse=failed")).unwrap();
        let (_, d) = judge_proxy_config(&inactive);
        assert!(d.contains("squid is inactive") && d.contains("squid -k parse"), "{d}");
        let mut changed = vals.clone();
        changed.insert(param_name("extras"), param(&format!("{}github.com\tai-env\n", super::super::EXTRAS_HEADER)));
        let (v, d) = judge_parameters(Some(&st), &changed, &[]);
        assert!(v == Verdict::Drift && d.starts_with("extras: the proxy reads sha256"), "{d}");
        // Odd bytes in a hash never panic: drift naming the key.
        for odd in ["zz", "é", &"A".repeat(64), &"0".repeat(63)] {
            let bad = parse_reload_status(&status_of(&vals, " applied=yes").replace(&format!("sha256_extras={}", value_sha256(super::super::EXTRAS_HEADER)), &format!("sha256_extras={odd}"))).unwrap();
            let (v, d) = judge_parameters(Some(&bad), &vals, &[]);
            assert!(v == Verdict::Drift && d.contains("sha256_extras is not 64 hex digits"), "{odd}: {d}");
        }
        let mut bad = vals.clone();
        bad.insert(param_name("allow"), param("1.2.3.4\n"));
        assert!(judge_parameters(None, &bad, &[]).1.contains("allow: line 1"));
        assert!(judge_parameters(None, &vals, &[param_name("suspended")]).1.contains("missing /ai-env/proxy/suspended"));
        assert_eq!(judge_parameters(None, &vals, &[]).0, Verdict::Ok);
    }

    #[test]
    fn squid_conf_and_allow_must_be_what_the_stack_rendered() {
        let vals = values();
        let state = InfraState { squid_conf_sha256: Some(value_sha256("http_port 10.42.0.10:3128\n")), allow_sha256: Some(value_sha256("api.anthropic.com\n").to_ascii_uppercase()), ..InfraState::default() };
        assert_eq!(judge_stack_params(&vals, &state).0, Verdict::Ok);
        let mut edited = vals.clone();
        edited.insert(param_name("squid.conf"), param("http_port 10.42.0.10:3128\nhttp_access allow all\n"));
        let (v, d) = judge_stack_params(&edited, &state);
        assert!(v == Verdict::Drift && d.contains("squid.conf differs from what the stack rendered"), "{d}");
        let (v, d) = judge_stack_params(&vals, &InfraState { allow_sha256: None, ..state.clone() });
        assert!(v == Verdict::Unknown && d.contains("no valid allow_sha256") && d.contains("make infra-status WRITE=1"), "{d}");
        assert_eq!(judge_stack_params(&vals, &InfraState { squid_conf_sha256: Some("abc".into()), ..state }).0, Verdict::Unknown);
    }

    #[test]
    fn a_removal_is_proved_by_the_status_taken_with_the_reload() {
        let value = format!("{}github.com\tother\n", super::super::EXTRAS_HEADER);
        let st = |applied: &str, extras: &str| -> BTreeMap<String, String> { [("applied".to_string(), applied.to_string()), ("sha256_extras".to_string(), value_sha256(extras))].into() };
        verify_applied(Some(&st("yes", &value)), "extras", &value).unwrap();
        assert!(verify_applied(Some(&st("no", &value)), "extras", &value).unwrap_err().contains("applied=no"));
        assert!(verify_applied(Some(&st("yes", "other")), "extras", &value).unwrap_err().contains("another extras"));
        assert!(verify_applied(None, "extras", &value).unwrap_err().contains("no --status line"));
        assert!(verify_applied(Some(&st("yes", &value)), "suspended", &value).unwrap_err().contains("no sha256_suspended"));
    }

    #[test]
    fn the_effective_set_with_another_value() {
        let l = Lists {
            allow: vec!["api.anthropic.com".into()],
            extras: parse_extras("github.com\tai-env\nexample.org\tai-env\n").unwrap(),
            suspended: ["example.org".to_string()].into(),
            raw: BTreeMap::new(),
        };
        let set = |v: BTreeSet<String>| v.into_iter().collect::<Vec<_>>();
        assert_eq!(set(l.effective_with("extras", &format!("{}github.com\tai-env\n", super::super::EXTRAS_HEADER)).unwrap()), ["api.anthropic.com", "github.com"]);
        assert_eq!(set(l.effective_with("suspended", super::super::SUSPENDED_HEADER).unwrap()), ["api.anthropic.com", "example.org", "github.com"]);
        assert_eq!(set(l.effective_with("suspended", "github.com\napi.anthropic.com\n").unwrap()), ["example.org"]);
        assert!(l.effective_with("extras", "github.com\n").is_err());
    }

    #[test]
    fn the_patch_takes_the_newest_release_and_shows_before_and_after() {
        assert!(PATCH_SCRIPT.contains(&"dnf -y upgrade --security --releasever=latest"));
        let at = |s: &str| PATCH_SCRIPT.iter().position(|c| c.contains(s)).unwrap();
        assert!(PATCH_SCRIPT[0] == "set -e" && at("before:") < at("dnf -y") && at("dnf -y") < at("after:") && at("after:") < at("systemctl restart squid"));
        assert!(PATCH_SCRIPT[at("before:")].contains("rpm -q system-release") && PATCH_SCRIPT[at("after:")].contains("rpm -q squid"));
    }

    #[test]
    fn extras_editing_keeps_a_host_while_any_slug_lists_it() {
        let mut ex = parse_extras("github.com\tai-env,other\n").unwrap();
        assert!(!edit_extras(&mut ex, "ai-env", "github.com", false), "already listed");
        assert!(edit_extras(&mut ex, "third", "static.rust-lang.org", false));
        assert!(edit_extras(&mut ex, "ai-env", "github.com", true));
        assert_eq!(ex.iter().find(|e| e.host == "github.com").unwrap().slugs.iter().cloned().collect::<Vec<_>>(), ["other"]);
        assert!(edit_extras(&mut ex, "other", "github.com", true));
        assert!(ex.iter().all(|e| e.host != "github.com"), "the last slug takes the host");
        assert!(!edit_extras(&mut ex, "other", "github.com", true));
        assert_eq!(render_extras(&ex), format!("{}static.rust-lang.org\tthird\n", super::super::EXTRAS_HEADER));
    }

    #[test]
    fn ids_and_the_proxy_address() {
        assert!(is_aws_id("i-0123456789abcdef0", "i-") && is_aws_id("sg-0123abcd", "sg-"));
        for bad in ["i-", "i-0123456789ABCDEF0", "--instance-ids", "i-0123456789abcdef0 x", "sg-0123456789abcdef0", "i-0123456789abcdef"] {
            assert!(!is_aws_id(bad, "i-"), "{bad}");
        }
        let cfg = BridgeConfig::default();
        assert_eq!(proxy_ip(&cfg, None), PROXY_IP);
        let state = InfraState { proxy_private_ip: Some("10.42.0.11".into()), ..InfraState::default() };
        assert_eq!(proxy_ip(&cfg, Some(&state)), "10.42.0.11");
        let set = BridgeConfig::parse("[aws]\nproxy_private_ip = \"192.168.1.5\"\n").unwrap();
        assert_eq!(proxy_ip(&set, Some(&state)), "192.168.1.5");
        let public = InfraState { proxy_private_ip: Some("8.8.8.8".into()), ..InfraState::default() };
        assert_eq!(proxy_ip(&cfg, Some(&public)), PROXY_IP, "never a public address");
    }
}
