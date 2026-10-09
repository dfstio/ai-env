//! `ai-env vm exec`, `vm attach`, `vm health --detail` and `vm smoke --exec`
//! (plan S6, W4) on top of [`super::run_spawn`].
//!
//! - **Before any Touch ID** ([`check_exec`], [`check_attach`],
//!   [`check_detail`]): the flags (a VM id; argv non-empty within
//!   `ARGV_MAX_BYTES`; `--cwd` absolute without `.`/`..`; `--env NAME=VALUE`
//!   names `[A-Za-z_][A-Za-z0-9_]*`, at most `ENV_MAX_ENTRIES`, each once; a
//!   `spawn` frame within `CONTROL_FRAME_MAX`; `--spawn` a uuid v7), then the
//!   row: it must hold a session token (only VMs `ai-env vm run` started),
//!   must not record the VM as terminated (exit 8), and must not be a
//!   `--shell` row (exit 9: the platform shell's in-VM listener is not yet
//!   shown unreachable from the agent). `--env` refuses (exit 9) `CLAUDECODE`,
//!   `NODE_OPTIONS`, `AWS_*`, any name with TOKEN, KEY, SECRET or PASSWORD, the
//!   shim's own HOME, PATH and CLAUDE_CONFIG_DIR, and on vpc rows the six
//!   proxy names ai-env sets itself — every name in any case; an error names
//!   a refused name, never a value. With a credential (S7) `check_exec` also
//!   runs `credential::check`: the flags, `[creds]`, `claude --bare`, the
//!   row's shim capabilities, the gate's local half and the sealed file
//!   (exits 1, 2, 5, 7, 9).
//! - **Running** ([`run_exec`], [`run_attach`]): GetMicrovm first (gone or
//!   going: exit 8), then one session. vpc rows get `egress::proxy_env` before
//!   the operator's `--env`. stdin is read in `CHUNK_MAX` pieces on its own
//!   thread (EOF → `stdin_eof`); `vm attach` forwards it only from a terminal:
//!   anything else (a script, `</dev/null`) leaves the remote's stdin as it
//!   is, where an EOF would close it for good. stdout and stderr each have a
//!   writer thread, so a blocked stdout never holds stderr back, and every
//!   chunk is marked in `Consumed` only once written and flushed. A note of
//!   the session is one `ai-env: …` line on stderr; the spawn's id and pid
//!   are logged, and shown when stderr is a terminal; a growing stderr
//!   `dropped` count is said at most once a second (a timer says what that
//!   held back), and its total at the exit. No PTY.
//! - **Signals.** SIGINT → `signal INT` (a second within 3 s → KILL); SIGTERM
//!   or SIGHUP → TERM, then at most 2 s for the exit, else `detach final`;
//!   EPIPE on stdout → TERM and `detach final` at once. While the session
//!   reconnects (its `SpawnEvent::Link` tells the pump so) nothing reaches
//!   the VM: a Ctrl-C is queued with a line saying so, and a second within
//!   3 s gives up (exit 130); the `detach final` of SIGTERM, SIGHUP or EPIPE
//!   waits for the connection at most `DELIVER_UNITS` of the session's
//!   seconds (another signal: not at all). Once the connection is back, TERM
//!   goes out first; SIGTERM and SIGHUP then give the command 2 s before
//!   `detach final`, while a closed stdout sends `detach final` right after
//!   TERM. A stop that never reached the VM ends with a
//!   line: the spawn may run until its detach grace ends it, and
//!   `vm attach` can stop it sooner. Before the spawn runs
//!   (for `vm attach`: before it is reattached) any of the three gives up
//!   instead of being queued for a command that would start once a socket
//!   comes up: `vm exec` sends `detach final`, which ends the session at its
//!   next wait (a spawn already on its way gets the signal, then `detach
//!   final`, as it starts); `vm attach` drops its attempt and leaves the spawn
//!   as it was. A second signal then stops waiting at once. A signal ignored
//!   when ai-env started (`nohup`, a non-interactive shell's background job)
//!   stays ignored, as ssh leaves it. After a detach the session gets at most
//!   3 s to send it; once the operator asked to stop, a stdout nobody reads
//!   holds the exit at most 3 s more, and another signal ends it at once. A
//!   credentialed `vm exec` listens from its first Touch ID on (S7): until
//!   the pump takes over, a stop drops what is under way (GetMicrovm, a gate
//!   read, the token's own unseal and its dialog) and ends it at once, 130 or
//!   143 with a line saying nothing was sent.
//! - **Exit status** (S6 D8): the remote code verbatim, 128 + N for a signal,
//!   through a silent `CliError::Exit` — also after a SIGINT the spawn got
//!   (the remote decides what INT means). The operator's own endings win over
//!   the remote's: 143 after SIGTERM or SIGHUP (whatever the remote did within
//!   the 2 s; plan S6), 130 after a SIGINT before the spawn ran (or a second
//!   one while nothing reached the VM), 0 after EPIPE, and 130/143 for a
//!   signal that cut the last flush short. ai-env's own failures keep 7/8/9
//!   with their `ai-env:` line (with a credential also 3, 4 and 5, and 130 or
//!   143 for a stop before the command started); a watched credentialed
//!   `claude` whose token Anthropic refuses ends with 5 and an `ai-env:` line
//!   instead of its own status (D6 amends D8). That line is stderr's last
//!   piece, written by stderr's writer like the rest, never by the exiting
//!   thread (a stderr nobody reads, or one pipe for both streams, full, would
//!   hold that thread for good), and no stop signal after the refusal changes
//!   the 5: the SIGTERM and SIGHUP sent during its stop or its child-gone
//!   check all end that check, and the last flush is then bounded as a stop's
//!   is; a signal that cuts the flush short leaves stderr at most a second
//!   more to take the line, and a stderr nobody reads leaves the 5 silent.
//!   The shim's limit of live
//!   spawns is a refusal (9) naming `vm health --detail`. One `vm_exec` /
//!   `vm_attach` audit row: the id, argv[0]'s basename, the spawn, the status
//!   and the time — never an argument or the environment.
//! - **`vm smoke --exec`** ([`smoke_exec`]): `claude --version`, `id -u` and,
//!   on vpc, `curl` to the API (401 through the proxy) and the proxy variable
//!   count, each a session of its own with an in-memory consumer, bounded by
//!   120 s.
use super::credential::{CredentialFlags, CredentialPlan, CredentialSupply};
use super::{run_spawn_with, spawn_channels, AgentEnv, AgentTarget, Consumed, ConsumerIo, Delivery, RunPolicy, SpawnEvent, SpawnInput, SpawnSpec, Start};
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo};
use crate::bridge::authwatch::{AuthWatch, Stream as WatchStream, Verdict, RETRY_LIMIT};
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::AgentDial;
use crate::bridge::vm::cmd::{audit_event, Ctx};
use crate::bridge::vm::registry::{self, RowStatus, VmRow};
use crate::errors::{CliError, Result};
use crate::outln;
use crate::wire::frame::{Deliver, Frame, HealthDetail, HookPeerSeen, Sig, SpawnId, ARGV_MAX_BYTES, CHUNK_MAX, CONTROL_FRAME_MAX, DETACH_GRACE_EXEC_S, ENV_MAX_ENTRIES, MAX_SPAWNS};
use crate::wire::redact::{scrub, Secret};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// stdin chunks queued ahead of the session.
const STDIN_SLOTS: usize = 16;
/// A second SIGINT within this sends KILL.
const KILL_WINDOW: Duration = Duration::from_secs(3);
/// S7 D6: after the TERM that stops a command whose credential was refused,
/// how long before KILL and the final detach.
const REJECT_KILL_AFTER: Duration = Duration::from_secs(3);
/// S7 D6, the child-gone check: how long after that stop `/health/detail`
/// may take to show the command gone before `vm exec` names `vm terminate`.
const REJECT_GONE_WITHIN: Duration = Duration::from_secs(5);
/// How often the child-gone check reads `/health/detail`.
const GONE_EVERY: Duration = Duration::from_millis(250);
/// After SIGTERM/SIGHUP: how long the remote gets to exit before `detach final`.
const TERM_WAIT: Duration = Duration::from_secs(2);
/// After a `detach`: how long the session gets to send it.
const DETACH_WAIT: Duration = Duration::from_secs(3);
/// While the session reconnects, a stop's `detach final` waits for the link
/// at most this many of the session's seconds (`RunPolicy::backoff_min`, the
/// unit of its reconnect steps: a short blip is a few of them).
const DELIVER_UNITS: u32 = 10;
/// The status `vm exec` exits with after SIGTERM/SIGHUP.
const TERM_STATUS: i32 = 128 + libc::SIGTERM;
/// The status after a SIGINT that came before the spawn ran, a second one while nothing reached the VM, or a Ctrl-C that ended the last flush.
const INT_STATUS: i32 = 128 + libc::SIGINT;
/// S7 D6: a refused credential's status (`CliError::AuthUnavailable`'s),
/// exited silently: its `ai-env:` line is stderr's last piece (`pump`).
const REJECTED_STATUS: i32 = 5;
/// S7 D6: once a signal cut a refused credential's last flush short, how much
/// longer stderr's writer may take to write that line out.
const LINE_WAIT: Duration = Duration::from_secs(1);
/// At most one stderr-dropped note this often.
const DROPPED_NOTE_EVERY: Duration = Duration::from_secs(1);
/// Each `vm smoke --exec` step.
const SMOKE_STEP_LIMIT: Duration = Duration::from_secs(120);
/// Most bytes of a smoke step's stdout or stderr kept.
const CAPTURE_MAX: usize = 64 * 1024;

/// Names `--env` never passes (any case): they change how claude or node start.
const STARTUP_NAMES: [&str; 2] = ["CLAUDECODE", "NODE_OPTIONS"];
/// What a name holding one of these looks like: a credential.
const CREDENTIAL_WORDS: [&str; 4] = ["TOKEN", "KEY", "SECRET", "PASSWORD"];
/// The shim sets these for the agent (`spawn` refuses them).
const RESERVED_NAMES: [&str; 3] = ["HOME", "PATH", "CLAUDE_CONFIG_DIR"];
/// The variables `egress::proxy_env` adds on vpc VMs.
const PROXY_VARS: usize = 6;

/// `vm exec` as validated before the Touch ID: the row it runs on and the
/// command. `Debug` shows argv[0]'s basename and counts, never an argument,
/// a value or the row's session token.
#[derive(Clone, PartialEq)]
pub struct ExecPlan {
    pub id: String,
    pub row: VmRow,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub detach_grace_s: Option<u32>,
    pub argv: Vec<String>,
    /// `--with-credential` / `--credential-file` (S7), as checked.
    pub credential: Option<CredentialPlan>,
}

impl std::fmt::Debug for ExecPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExecPlan({}, argv0={}, argc={}, env={}, cwd={}, detach_grace_s={:?}, credential={})",
            self.id,
            argv0(&self.argv),
            self.argv.len(),
            self.env.len(),
            if self.cwd.is_some() { "set" } else { "default" },
            self.detach_grace_s,
            match &self.credential {
                None => "none",
                Some(c) if c.file.is_some() => "file",
                Some(_) => "sealed",
            }
        )
    }
}

/// `vm attach` as validated before the Touch ID. `Debug` never shows the row.
#[derive(Clone, PartialEq)]
pub struct AttachPlan {
    pub id: String,
    pub row: VmRow,
    pub spawn_id: SpawnId,
    pub from_seq: Option<u64>,
}

impl std::fmt::Debug for AttachPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AttachPlan({}, spawn={}, from_seq={:?})", self.id, self.spawn_id, self.from_seq)
    }
}

/// The basename of argv[0] (what logs and the audit may show).
fn argv0(argv: &[String]) -> &str {
    argv.first().map_or("", |a| a.rsplit('/').next().unwrap_or(a))
}

// ---- validation (no AWS, no Touch ID) ----------------------------------------------

/// Validate `vm exec`'s flags and the VM's row (see the module doc), and
/// the credential's local conditions (`credential::check`, S7).
pub fn check_exec(ctx: &Ctx, id: &str, cwd: Option<String>, env: &[String], detach_grace_s: Option<u32>, argv: Vec<String>, cred: &CredentialFlags) -> Result<ExecPlan> {
    check_id(id)?;
    if argv.is_empty() {
        return Err(CliError::Usage("vm exec: nothing to run (give the command after --)".into()));
    }
    if argv[0].is_empty() {
        return Err(CliError::Usage("vm exec: the command (argv[0]) is empty".into()));
    }
    let size: usize = argv.iter().map(|a| a.len() + 1).sum();
    if size > ARGV_MAX_BYTES {
        return Err(CliError::Usage(format!("vm exec: the command line is {size} bytes (at most {ARGV_MAX_BYTES})")));
    }
    if let Some(dir) = &cwd {
        check_cwd(dir)?;
    }
    let env = parse_env(env)?;
    let row = agent_row(ctx, id, "run commands")?;
    if row.egress == "vpc" {
        if let Some((name, _)) = env.iter().find(|(k, _)| is_proxy_name(k)) {
            return Err(BridgeError::Policy(format!("--env {name}: ai-env sets the six proxy variables itself on vpc VMs")).into());
        }
        if env.len() + PROXY_VARS > ENV_MAX_ENTRIES {
            return Err(CliError::Usage(format!("--env: {} variables (at most {} on a vpc VM, which also gets the {PROXY_VARS} proxy variables)", env.len(), ENV_MAX_ENTRIES - PROXY_VARS)));
        }
    }
    let mut plan = ExecPlan { id: id.to_string(), row, cwd, env, detach_grace_s, argv, credential: None };
    check_frame(&plan)?;
    plan.credential = super::credential::check(&ctx.cfg, &ctx.paths, &plan.row, &plan.argv, cred)?;
    Ok(plan)
}

/// Validate `vm attach`'s flags and the VM's row.
pub fn check_attach(ctx: &Ctx, id: &str, spawn: &str, from_seq: Option<u64>) -> Result<AttachPlan> {
    check_id(id)?;
    let spawn_id = SpawnId(spawn.to_string());
    if !spawn_id.is_v7() {
        return Err(CliError::Usage(format!("--spawn {spawn:?}: expected the spawn's uuid (v7), as vm exec printed it")));
    }
    if from_seq == Some(0) {
        return Err(CliError::Usage("--from-seq: stdout seqs start at 1".into()));
    }
    let row = agent_row(ctx, id, "run commands")?;
    Ok(AttachPlan { id: id.to_string(), row, spawn_id, from_seq })
}

/// Validate `vm health --detail`: the id, and a row holding the session token
/// (the bearer); `--shell` rows may read it.
pub fn check_detail(ctx: &Ctx, id: &str) -> Result<VmRow> {
    check_id(id)?;
    read_agent_row(ctx, id, "read /health/detail")
}

fn check_id(id: &str) -> Result<()> {
    if registry::is_vm_id(id) {
        Ok(())
    } else {
        Err(CliError::Usage(format!("not a microvm id: {id:?}")))
    }
}

/// `--cwd`: absolute, no `.` or `..` component (the shim's own rule).
fn check_cwd(dir: &str) -> Result<()> {
    if !dir.starts_with('/') || dir.split('/').any(|p| p == "." || p == "..") {
        return Err(CliError::Usage("--cwd: expected an absolute path without . or .. components".into()));
    }
    Ok(())
}

/// The `--env` pairs: syntax and names (usage), the refused names (policy).
/// Errors name a variable only once its name is valid, and never a value.
fn parse_env(env: &[String]) -> Result<Vec<(String, String)>> {
    if env.len() > ENV_MAX_ENTRIES {
        return Err(CliError::Usage(format!("--env: {} variables (at most {ENV_MAX_ENTRIES})", env.len())));
    }
    let mut out: Vec<(String, String)> = Vec::with_capacity(env.len());
    for (i, kv) in env.iter().enumerate() {
        let n = i + 1;
        let Some((name, value)) = kv.split_once('=') else {
            return Err(CliError::Usage(format!("--env #{n}: expected NAME=VALUE")));
        };
        if !is_env_name(name) {
            return Err(CliError::Usage(format!("--env #{n}: the name must match [A-Za-z_][A-Za-z0-9_]*")));
        }
        if let Some(why) = refused_name(name) {
            return Err(BridgeError::Policy(format!("--env {name}: {why}")).into());
        }
        if out.iter().any(|(k, _)| k == name) {
            return Err(CliError::Usage(format!("--env {name} is given twice")));
        }
        out.push((name.to_string(), value.to_string()));
    }
    Ok(out)
}

fn is_env_name(k: &str) -> bool {
    k.bytes().next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Why `vm exec` never passes `name` (any case), or `None`.
fn refused_name(name: &str) -> Option<&'static str> {
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("AWS_") {
        Some("vm exec never passes AWS_* variables (credentials reach the VM only through ai-env's own delivery)")
    } else if STARTUP_NAMES.contains(&upper.as_str()) {
        Some("it changes how claude and node start in the VM")
    } else if RESERVED_NAMES.contains(&upper.as_str()) {
        Some("the shim sets it for the agent")
    } else if CREDENTIAL_WORDS.iter().any(|w| upper.contains(w)) {
        Some("a name with TOKEN, KEY, SECRET or PASSWORD looks like a credential, and vm exec never passes one in the environment")
    } else {
        None
    }
}

/// One of the six proxy variables `egress::proxy_env` sets (any case).
fn is_proxy_name(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "https_proxy" | "http_proxy" | "no_proxy")
}

/// The `spawn` frame must stay within `CONTROL_FRAME_MAX` (the shim closes the socket otherwise).
fn check_frame(plan: &ExecPlan) -> Result<()> {
    let frame = Frame::Spawn {
        spawn_id: SpawnId::new_v7(),
        argv: plan.argv.clone(),
        cwd: plan.cwd.clone(),
        env: plan.env.iter().cloned().collect(),
        secrets: BTreeMap::new(),
        deliver_secret: Deliver::Fd,
        detach_grace_s: plan.detach_grace_s,
        credential: None,
    };
    let size = frame.to_json().len();
    if size > CONTROL_FRAME_MAX {
        return Err(CliError::Usage(format!("vm exec: the command and its environment make a {size}-byte spawn frame (at most {CONTROL_FRAME_MAX})")));
    }
    Ok(())
}

/// The row of a VM the agent runs on: a session token, not terminated, no `--shell`.
fn agent_row(ctx: &Ctx, id: &str, what: &str) -> Result<VmRow> {
    let row = read_agent_row(ctx, id, what)?;
    if row.status == RowStatus::Terminated {
        let by = row.terminated_by.as_deref().map(|b| format!(", by {b}")).unwrap_or_default();
        return Err(BridgeError::Terminated(format!("{id}: its row records the VM as terminated{by}; start one with `ai-env vm run`")).into());
    }
    if row.shell {
        return Err(BridgeError::Policy(format!(
            "{id} was started with --shell: vm exec stays refused on such VMs until the platform shell's in-VM listener is shown unreachable from the agent (ai-env lab run in-vm-firewall); start a VM without --shell"
        ))
        .into());
    }
    Ok(row)
}

/// The row of `id` with a session token (exit 1 naming `vm run` otherwise).
fn read_agent_row(ctx: &Ctx, id: &str, what: &str) -> Result<VmRow> {
    let Some(row) = registry::read_row(&ctx.paths, id)? else {
        return Err(CliError::Msg(format!("{id} has no row in state/vms: only VMs `ai-env vm run` started (whose row holds the session token) can {what}")));
    };
    if row.session_token.as_deref().is_none_or(str::is_empty) {
        return Err(CliError::Msg(format!("{id}: its row holds no session token: only VMs `ai-env vm run` started can {what}")));
    }
    Ok(row)
}

// ---- running ----------------------------------------------------------------------

/// GetMicrovm: a VM that is gone or going is exit 8 naming its state.
async fn live_vm<A: MicrovmApi>(api: &A, id: &str) -> Result<VmInfo> {
    let vm = api.get(id).await?;
    if vm.state.is_terminal() {
        let reason = vm.state_reason.as_deref().map(|r| format!(" ({})", scrub(r))).unwrap_or_default();
        return Err(BridgeError::Terminated(format!("{id} is {}{reason}", vm.state.as_str())).into());
    }
    Ok(vm)
}

/// The spawn environment: `egress::proxy_env` on vpc rows, then the operator's pairs.
pub(crate) fn spawn_env(ctx: &Ctx, row: &VmRow, user: &[(String, String)]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if row.egress == "vpc" {
        let state = crate::bridge::infra::read_infra_state(&ctx.paths).ok().flatten();
        let (ip, _) = crate::bridge::egress::effective_proxy_ip(ctx.cfg.aws.proxy_private_ip.as_deref(), state.as_ref());
        env.extend(crate::bridge::egress::proxy_env(ip, crate::bridge::egress::PROXY_PORT).into_iter().map(|(k, v)| (k.to_string(), v)));
    }
    env.extend(user.iter().cloned());
    env
}

/// The session's surroundings for `row` (the endpoint GetMicrovm reported wins over the row's).
pub(crate) fn agent_env<'a, A: MicrovmApi, E: EndpointClient>(ctx: &'a Ctx, api: &'a A, ep: &'a E, row: &VmRow, vm: Option<&VmInfo>) -> Result<AgentEnv<'a, A, E>> {
    let mut row = row.clone();
    if let Some(endpoint) = vm.map(|v| v.endpoint.clone()).filter(|e| !e.is_empty()) {
        row.endpoint = Some(endpoint);
    }
    let target = AgentTarget::from_row(&row)?;
    let dial = AgentDial { local: ctx.knobs.agent_addr().map_err(CliError::Usage)? };
    Ok(AgentEnv { api, ep, paths: &ctx.paths, target, policy: RunPolicy::from_cfg(&ctx.cfg.transport, &row, ctx.knobs.backoff_ms), dial })
}

/// `vm exec`; with a credential, the gate, the token and its delivery first
/// (`credential::prepare`, S7). A credentialed exec listens for its stop
/// signals from its first Touch ID on (`crate::bridge::signals`): until the
/// pump takes the listeners, a stop drops whatever is under way at once
/// (GetMicrovm, a gate read, the token's own unseal and its dialog) and ends
/// the command with 130 or 143 and a line saying nothing was sent.
pub async fn run_exec<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, plan: ExecPlan, supply: Option<CredentialSupply<'_>>) -> Result<()> {
    use crate::bridge::signals::{say, stoppable, Stops};
    let started = Instant::now();
    let name = argv0(&plan.argv).to_string();
    let run = async {
        let mut stops = match &plan.credential {
            Some(_) => Some(Stops::take()?),
            None => None,
        };
        let ready = async {
            let vm = live_vm(api, &plan.id).await?;
            let env = agent_env(ctx, api, ep, &plan.row, Some(&vm))?;
            let spec = SpawnSpec { argv: plan.argv.clone(), cwd: plan.cwd.clone(), env: spawn_env(ctx, &plan.row, &plan.env), detach_grace_s: plan.detach_grace_s };
            let delivery = match (&plan.credential, supply) {
                (Some(cp), Some(supply)) => Some(super::credential::prepare(ctx, api, ep, &plan.row, &vm, cp, supply).await?.delivery),
                (Some(_), None) => return Err(CliError::Msg("internal: a credentialed exec without its keystore".into())),
                (None, _) => None,
            };
            Ok::<_, CliError>((env, spec, delivery))
        };
        let (env, spec, delivery) = match stops.as_mut() {
            Some(stops) => match stoppable(stops, ready).await {
                Ok(r) => r?,
                Err(stop) => {
                    say(&format!("ai-env: {} ({}) before the command started on {}: nothing was sent", stop.word(), stop.name(), plan.id));
                    return Err(CliError::Exit(stop.status()));
                }
            },
            None => ready.await?,
        };
        // The pump's own listeners are these, with any signal that came since (`signals::handle`).
        if let Some(stops) = stops {
            stops.keep();
        }
        pump(&env, Start::New(spec), true, delivery, plan.credential.as_ref()).await
    };
    let pumped = run.await;
    let rejected = pumped.as_ref().ok().and_then(|p| p.rejected);
    let (result, spawn) = finish(pumped);
    if let (Some(r), Some(cred)) = (rejected, &plan.credential) {
        super::credential::record_rejection(&ctx.paths, &plan.id, &cred.tag, r.how);
    }
    audit_run(ctx, "vm_exec", &plan.id, &name, spawn.as_ref(), &result, started);
    result
}

/// `vm attach`: the same consumer on a reattach (`gap` and an unknown spawn
/// are exit 8). Its stdin replaces the remote's only from a terminal: an EOF
/// from a script or `</dev/null` would close the remote's stdin for good.
pub async fn run_attach<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, plan: AttachPlan) -> Result<()> {
    let started = Instant::now();
    let run = async {
        let vm = live_vm(api, &plan.id).await?;
        let env = agent_env(ctx, api, ep, &plan.row, Some(&vm))?;
        let stdin = std::io::stdin().is_terminal();
        if !stdin {
            tracing::info!("vm {}: stdin is not a terminal: the remote's stdin is left as it is", plan.id);
        }
        pump(&env, Start::Attach { spawn_id: plan.spawn_id.clone(), from_seq: plan.from_seq, err_from_seq: None }, stdin, None, None).await
    };
    let (result, spawn) = finish(run.await);
    audit_run(ctx, "vm_attach", &plan.id, "-", spawn.as_ref().or(Some(&plan.spawn_id)), &result, started);
    result
}

/// What one attachment came to: the status to exit with (0 = success) or
/// ai-env's own failure, and the spawn once known.
struct Pumped {
    result: std::result::Result<i32, CliError>,
    spawn: Option<SpawnId>,
    /// S7 D6: the delivered credential was refused.
    rejected: Option<Rejected>,
}

/// `Pumped` → the command's result (0: `Ok`; a remote status: the silent `Exit`).
fn finish(r: Result<Pumped>) -> (Result<()>, Option<SpawnId>) {
    match r {
        Ok(Pumped { result: Ok(0), spawn, .. }) => (Ok(()), spawn),
        Ok(Pumped { result: Ok(status), spawn, .. }) => (Err(CliError::Exit(status)), spawn),
        Ok(Pumped { result: Err(e), spawn, .. }) => (Err(e), spawn),
        Err(e) => (Err(e), None),
    }
}

fn audit_run(ctx: &Ctx, event: &str, id: &str, argv0: &str, spawn: Option<&SpawnId>, result: &Result<()>, started: Instant) {
    let status = match result {
        Ok(()) => 0,
        Err(e) => e.exit_code(),
    };
    let spawn = spawn.map_or_else(|| "-".to_string(), ToString::to_string);
    audit_event(&ctx.paths, event, &[("id", id.to_string()), ("argv0", argv0.to_string()), ("spawn", spawn), ("status", status.to_string()), ("ms", started.elapsed().as_millis().to_string())]);
}

/// How the operator ended the attachment: their status wins over the remote's.
#[derive(Debug)]
enum Ending {
    /// SIGTERM/SIGHUP: exit 143.
    Term,
    /// SIGINT before the spawn ran, or a second one while nothing reached the VM: exit 130.
    Interrupted,
    /// stdout failed: exit 0 for a broken pipe, else 1 naming the error.
    Stdout(std::io::Error),
    /// S7 D6: the third retry 401 of the delivered credential: TERM, then
    /// KILL and the final detach, then the child-gone check; exit 5, never a
    /// respawn.
    CredentialRejected,
}

impl Ending {
    fn result(self) -> std::result::Result<i32, CliError> {
        match self {
            Ending::Term => Ok(TERM_STATUS),
            Ending::Interrupted => Ok(INT_STATUS),
            Ending::Stdout(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(0),
            Ending::Stdout(e) => Err(CliError::Msg(format!("vm exec: writing stdout failed ({e}); the remote command was stopped"))),
            // `pump` says what it saw instead; without that, nothing is claimed.
            Ending::CredentialRejected => Err(CliError::AuthUnavailable(rejected_text(Rejected { how: "retries", end: RejectedEnd::Unconfirmed }, None))),
        }
    }
}

/// S7 D6: the delivered credential was refused. `how` is the audit's
/// (`retries` or `text`); `end` is what `vm exec` saw of the command's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rejected {
    how: &'static str,
    end: RejectedEnd,
}

/// What was seen of a refused credential's command ending: the exit-5 line
/// says that and no more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectedEnd {
    /// `vm exec` stopped it and saw it end: its exit came back, or the
    /// child-gone check found it and its group gone.
    Stopped,
    /// `vm exec` sent the stop but did not see it end (the lines before say
    /// what may still run, and `vm terminate`).
    Unconfirmed,
    /// It exited by itself (a text 401, then a failing exit).
    Exited,
}

/// The `ai-env:` line of a refused credential (exit 5): what was seen of the
/// command's end, and what to do: for the sealed setup-token, seal a fresh
/// one; for a `--credential-file` container with a seal of its own (`file`),
/// give another one, since the sealed setup-token is not affected.
fn rejected_text(r: Rejected, file: Option<&std::path::Path>) -> String {
    let end = match r.end {
        RejectedEnd::Stopped => "the command was stopped and is not started again",
        RejectedEnd::Unconfirmed => "the stop was sent, but the command was not seen to end (see above); it is not started again",
        RejectedEnd::Exited => "the command exited and is not started again",
    };
    match file {
        None => format!("Anthropic refused the delivered setup-token (HTTP 401): {end}; seal a fresh one with `claude setup-token`, then `ai-env creds setup-token`"),
        Some(f) => format!("Anthropic refused the delivered setup-token from {} (HTTP 401): {end}; commands given that container now refuse at once: give another one (the sealed setup-token is not affected)", f.display()),
    }
}

// The pump's listeners come from the bridge's one signal helper (S7): an ignored signal stays ignored as it
// was when ai-env started. A credentialed exec's are the ones `run_exec` kept: a stop during GetMicrovm, the
// gate or the token's unseal was `run_exec`'s own (nothing was sent), and one the runtime handed over only
// after that phase last looked waits in them for the pump ("before the command started … giving up").
use crate::bridge::signals::{delivered, handle};

/// One attachment with the process's stdio and signals (see the module doc);
/// `stdin`: this process's stdin feeds the remote's; `credential`: the
/// credentialed exec's, whose refusal's exit-5 line this writes (S7 D6).
async fn pump<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, start: Start, stdin: bool, delivery: Option<Delivery>, credential: Option<&CredentialPlan>) -> Result<Pumped> {
    use tokio::signal::unix::SignalKind;
    let (mut int, mut term, mut hup) = (handle(libc::SIGINT, SignalKind::interrupt())?, handle(libc::SIGTERM, SignalKind::terminate())?, handle(libc::SIGHUP, SignalKind::hangup())?);
    // `vm attach`'s spawn: a signal before it is reattached leaves it as it
    // was. `vm exec`'s: the detach grace the shim gives it once no socket carries it.
    let (reattach, grace) = match &start {
        Start::Attach { spawn_id, .. } => (Some(spawn_id.clone()), None),
        Start::New(spec) => (None, Some(spec.detach_grace_s.unwrap_or(DETACH_GRACE_EXEC_S))),
    };
    let (io, c) = spawn_channels(STDIN_SLOTS);
    let ConsumerIo { input, control, mut events, consumed } = c;
    if stdin {
        std::thread::Builder::new().name("vm-exec-stdin".into()).spawn(move || read_stdin(&input)).map_err(|e| CliError::Msg(format!("cannot start the stdin reader: {e}")))?;
    } else {
        // No chunk and no EOF: the remote's stdin stays as it is.
        drop(input);
    }
    let (broken_tx, mut broken) = mpsc::unbounded_channel();
    let out = Writer::start(Stream::Stdout, consumed.clone(), Some(broken_tx))?;
    let err = Writer::start(Stream::Stderr, consumed, None)?;
    let mut view = View::new(&env.target.vm_id);
    // S7 D6: a credentialed `claude`'s output is watched for a refused token.
    if let (Start::New(spec), Some(_)) = (&start, &delivery) {
        if super::credential::is_claude(&spec.argv) {
            view.watch = Some(AuthWatch::new());
        }
    }
    let mut session = Box::pin(run_spawn_with(env, start, io, delivery));
    // A stop's way out: the detach is sent at `detach_at` (TERM's wait), or
    // waits for the link until `held` while nothing reaches the VM; once sent,
    // the session gets until `give_up_at`.
    let (mut ending, mut detach_at, mut held, mut give_up_at, mut last_int) = (None::<Ending>, None, None, None, None::<Instant>);
    let detach = |control: &mpsc::UnboundedSender<SpawnInput>| {
        let _ = control.send(SpawnInput::Detach { is_final: true });
        Some(tokio::time::Instant::now() + DETACH_WAIT)
    };
    let deliver_wait = env.policy.backoff_min.saturating_mul(DELIVER_UNITS);
    let hold = |err: &Writer, vm: &str| {
        err.line(format!("ai-env: not connected to {vm} (reconnecting): stopping the command waits for the connection at most {} (another signal gives up)", secs(deliver_wait)));
        Some(tokio::time::Instant::now() + deliver_wait)
    };
    let outcome = loop {
        // The signal to act on (SIGHUP stands as TERM, the signal it sends).
        let got = tokio::select! {
            r = &mut session => break Some(r),
            Some(ev) = events.recv() => {
                let was = view.linked;
                view.event(ev, &out, &err);
                if view.rejected && ending.is_none() {
                    tracing::info!("vm {}: the credential was refused {RETRY_LIMIT} times: stopping the command", view.vm);
                    err.line(format!("ai-env: Anthropic refused the delivered setup-token ({RETRY_LIMIT} retries with HTTP 401): stopping the command, which is not started again"));
                    ending = Some(Ending::CredentialRejected);
                    let _ = control.send(SpawnInput::Signal(Sig::Term));
                    detach_at = Some(tokio::time::Instant::now() + REJECT_KILL_AFTER);
                }
                // Back on a socket: the TERM queued meanwhile went out with the
                // reattach, and the held detach follows (after TERM's wait).
                if view.linked && !was && held.take().is_some() {
                    let wait = if matches!(ending, Some(Ending::Term)) { TERM_WAIT } else { Duration::ZERO };
                    detach_at = Some(tokio::time::Instant::now() + wait);
                }
                continue;
            }
            () = at(view.dropped.due().map(tokio::time::Instant::from_std)) => {
                view.held_dropped(&err);
                continue;
            }
            Some(()) = delivered(&mut int) => Sig::Int,
            Some(()) = delivered(&mut term), if ending.is_none() || view.given_up || held.is_some() => Sig::Term,
            Some(()) = delivered(&mut hup), if ending.is_none() || view.given_up || held.is_some() => Sig::Term,
            Some(e) = broken.recv(), if ending.is_none() => {
                tracing::info!("vm {}: stdout failed ({e}): stopping the remote command", view.vm);
                ending = Some(Ending::Stdout(e));
                let _ = control.send(SpawnInput::Signal(Sig::Term));
                detach_at = Some(tokio::time::Instant::now());
                continue;
            }
            () = at(detach_at) => {
                detach_at = None;
                if matches!(ending, Some(Ending::CredentialRejected)) {
                    // TERM's time is up: KILL the group, then the attachment ends for good.
                    let _ = control.send(SpawnInput::Signal(Sig::Kill));
                }
                if view.linked {
                    give_up_at = detach(&control);
                } else {
                    held = hold(&err, &view.vm);
                }
                continue;
            }
            () = at(held) => {
                held = None;
                give_up_at = detach(&control);
                continue;
            }
            () = at(give_up_at) => break None,
        };
        match got {
            // Another signal while the stop waits for the link: give that up.
            _ if held.is_some() => {
                held = None;
                give_up_at = detach(&control);
            }
            Sig::Int if view.spawn.is_some() => {
                let again = last_int.is_some_and(|t| t.elapsed() < KILL_WINDOW);
                last_int = Some(Instant::now());
                if view.linked || ending.is_some() {
                    let sig = if again { Sig::Kill } else { Sig::Int };
                    tracing::info!("vm {}: SIGINT: sending {sig:?} to the remote group", view.vm);
                    let _ = control.send(SpawnInput::Signal(sig));
                } else if again {
                    // Nothing reaches the VM, and the operator insists: the spawn's grace ends it.
                    tracing::info!("vm {}: SIGINT again while not connected: giving up", view.vm);
                    ending = Some(Ending::Interrupted);
                    err.line(format!("ai-env: interrupted again while not connected to {}: giving up", view.vm));
                    give_up_at = detach(&control);
                } else {
                    err.line(format!(
                        "ai-env: not connected to {} (reconnecting): the interrupt reaches the command once the connection is back; Ctrl-C again within {} s gives up",
                        view.vm,
                        KILL_WINDOW.as_secs()
                    ));
                    let _ = control.send(SpawnInput::Signal(Sig::Int));
                }
            }
            // Another signal while giving up: stop waiting for the session.
            _ if view.given_up => break None,
            // Before the spawn runs, a signal is not queued for a command
            // that would start once a socket comes up: the attachment is given up.
            _ if view.spawn.is_none() => {
                let (what, why) = if got == Sig::Int { ("interrupted", Ending::Interrupted) } else { ("terminated", Ending::Term) };
                ending = Some(why);
                if let Some(id) = &reattach {
                    err.line(format!("ai-env: {what} before spawn {id} was reattached: leaving it as it was"));
                    break None;
                }
                view.given_up = true;
                err.line(format!("ai-env: {what} before the command started on {}: giving up", view.vm));
                // `detach final` ends the session at its next wait; a spawn
                // already on its way gets the signal, then the detach, as it starts.
                let _ = control.send(SpawnInput::Signal(got));
                give_up_at = detach(&control);
            }
            _ => {
                ending = Some(Ending::Term);
                let _ = control.send(SpawnInput::Signal(Sig::Term));
                if view.linked {
                    detach_at = Some(tokio::time::Instant::now() + TERM_WAIT);
                } else {
                    held = hold(&err, &view.vm);
                }
            }
        }
    };
    drop(session);
    while let Some(ev) = events.recv().await {
        view.event(ev, &out, &err);
    }
    drop(control);
    let detached = give_up_at.is_some();
    let mut stopping = matches!(ending, Some(Ending::Term | Ending::Interrupted));
    // The operator's stop went out while no socket carried the spawn (its
    // notes said the link was down to the end): the shim's grace decides.
    if detached && ending.is_some() && !view.linked && !matches!(outcome, Some(Ok(_))) {
        if let Some(id) = &view.spawn {
            let grace = grace.map(|s| format!(" ({s} s)")).unwrap_or_default();
            tracing::info!("vm {}: the stop of spawn {id} went out with no socket up: its detach grace{grace} ends it", view.vm);
            err.line(format!("ai-env: the stop could not reach {vm}: spawn {id} may keep running until its detach grace{grace} ends it; `ai-env vm attach {vm} --spawn {id}` can stop it sooner", vm = view.vm));
        }
    }
    let spawn = match &outcome {
        Some(Ok(o)) => Some(o.spawn_id.clone()),
        _ => view.spawn.clone(),
    };
    // S7 D6: the watch stopped it, and the child-gone check looks for it
    // (its exit coming back is not enough: the group may outlive the
    // leader); or it ended by itself after a text 401 (or after the retries,
    // read once the session had ended) with a failing status.
    let rejected = if matches!(ending, Some(Ending::CredentialRejected)) {
        // `None`: another signal ended the wait, and nothing is confirmed
        // then. Signals first: one sent during TERM's wait (still pending)
        // ends the check before its first read (which can answer within one
        // poll), so it never falls to the flush below, which it would cut short.
        let looked = tokio::select! {
            biased;
            Some(()) = delivered(&mut int) => None,
            Some(()) = delivered(&mut term) => None,
            Some(()) = delivered(&mut hup) => None,
            g = spawn_gone(env, spawn.as_ref()) => Some(g),
        };
        if looked.is_none() {
            // Every stop signal already here ends the check with it (SIGTERM
            // and SIGHUP both sent during TERM's wait), none left for the
            // flush. The runtime hands a signal over only when it looks for
            // events: one look first. The operator asked to stop, so the
            // last flush is bounded as a stop's is (no signal is left to end it).
            use futures_util::FutureExt as _;
            tokio::task::yield_now().await;
            for s in [&mut int, &mut term, &mut hup] {
                let _ = delivered(s).now_or_never();
            }
            stopping = true;
        }
        let gone = looked == Some(GoneCheck::Gone);
        if !gone {
            let what = spawn.as_ref().map_or_else(|| "the command".to_string(), |id| format!("spawn {id}"));
            err.line(not_seen_gone_line(&what, &view.vm, looked.as_ref()));
        }
        let end = if gone || matches!(outcome, Some(Ok(_))) { RejectedEnd::Stopped } else { RejectedEnd::Unconfirmed };
        Some(Rejected { how: "retries", end })
    } else {
        match &outcome {
            Some(Ok(o)) if ending.is_none() => view.watch.as_mut().and_then(|w| w.rejected_at_exit(o.exit.code).then(|| Rejected { how: if w.retries() >= RETRY_LIMIT { "retries" } else { "text" }, end: RejectedEnd::Exited })),
            _ => None,
        }
    };
    let result = match rejected {
        // S7 D6: ai-env's own failure (exit 5), saying what it saw of the end.
        // Its line is stderr's last piece, written by stderr's writer like the
        // rest: a stderr nobody reads holds that thread, never the exit, and
        // the 5 is silent. A `--credential-file` container with a seal of its
        // own is named, with advice about it (a byte copy of setup-token.env
        // is the sealed token's seal).
        Some(r) => {
            let own = credential.and_then(|c| c.file.as_deref().filter(|_| super::credential::seal_tag(&env.paths.setup_token_env()).as_deref() != Some(c.tag.as_str())));
            err.line(format!("ai-env: {}", rejected_text(r, own)));
            Ok(REJECTED_STATUS)
        }
        None => match (outcome, ending) {
            // ai-env's own failure while TERM's 2 s ran (or its detach waited for the link), before any detach.
            (Some(Err(e)), Some(Ending::Term)) if !detached => Err(session_error(e, &err, &view.vm)),
            // The operator ended it: their status, whatever the remote did (S6:
            // TERM, at most 2 s, then 143; a broken pipe is 0).
            (_, Some(e)) => e.result(),
            (Some(Ok(o)), None) => Ok(o.exit.status()),
            (Some(Err(e)), None) => Err(session_error(e, &err, &view.vm)),
            // The loop gives up only with an ending.
            (None, None) => Ok(TERM_STATUS),
        },
    };
    let pumped = Pumped { result, spawn, rejected };
    // Everything delivered is written before the process exits. Once the
    // operator asked to stop, a stdout or stderr nobody reads holds the exit
    // only `DETACH_WAIT`; another signal ends the wait at once. The two
    // streams are closed apart: a refusal's line is stderr's alone (below).
    let out_flushed = tokio::task::spawn_blocking(move || out.close());
    let mut err_flushed = tokio::task::spawn_blocking(move || err.close());
    let bound = stopping.then(|| tokio::time::Instant::now() + DETACH_WAIT);
    let cut = tokio::select! {
        _ = async { tokio::join!(out_flushed, &mut err_flushed) } => None,
        () = at(bound) => None,
        Some(()) = delivered(&mut term) => Some(TERM_STATUS),
        Some(()) = delivered(&mut hup) => Some(TERM_STATUS),
        Some(()) = delivered(&mut int) => Some(INT_STATUS),
    };
    Ok(match cut {
        None => pumped,
        // S7 D6: a signal that cuts a refusal's last flush short keeps exit
        // 5, and stderr's writer gets `LINE_WAIT` more for the line (another
        // signal ends that wait). A writer that finished is not waited on:
        // the join above may have polled it to its end, and a second poll panics.
        Some(_) if pumped.rejected.is_some() => {
            if !err_flushed.is_finished() {
                tokio::select! {
                    _ = tokio::time::timeout(LINE_WAIT, &mut err_flushed) => {}
                    Some(()) = delivered(&mut term) => {}
                    Some(()) = delivered(&mut hup) => {}
                    Some(()) = delivered(&mut int) => {}
                }
            }
            pumped
        }
        Some(status) => Pumped { result: Ok(status), ..pumped },
    })
}

/// S7 D6, the child-gone check after the stop of a refused credential's
/// command (TERM, then KILL and the final detach): `/health/detail` with the
/// row's bearer and one minted token, every [`GONE_EVERY`] until
/// [`REJECT_GONE_WITHIN`] after the check began, its mint included. A fresh
/// request, so it also sees a VM the stop's socket no longer reaches. A read
/// that fails, or never shows the spawn gone ([`gone_from`]), is not gone;
/// without a spawn id or a token no read is made, and the answer says why.
async fn spawn_gone<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, id: Option<&SpawnId>) -> GoneCheck {
    let Some(id) = id else { return GoneCheck::Unread("no spawn id came back".into()) };
    crate::wire::redact::register_secret(env.target.session_token.expose());
    let deadline = tokio::time::Instant::now() + REJECT_GONE_WITHIN;
    let token = match tokio::time::timeout_at(deadline, crate::bridge::vm::token::mint_internal(env.api, env.paths, &env.target.vm_id)).await {
        Ok(Ok(token)) => token,
        Ok(Err(e)) => return GoneCheck::Unread(format!("its token could not be minted: {}", scrub(&e.to_string()))),
        Err(_) => return GoneCheck::Unread(format!("its token was not minted within {} s", REJECT_GONE_WITHIN.as_secs())),
    };
    let poll = async {
        loop {
            match env.ep.get_health_detail(&env.target.endpoint, &token, &env.target.session_token).await {
                Ok(reply) if reply.status == 200 && reply.detail.as_ref().is_some_and(|d| gone_from(&d.spawns, id)) => return,
                _ => tokio::time::sleep(GONE_EVERY).await,
            }
        }
    };
    match tokio::time::timeout_at(deadline, poll).await {
        Ok(()) => GoneCheck::Gone,
        Err(_) => GoneCheck::NotSeenGone,
    }
}

/// What the child-gone check ([`spawn_gone`]) came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GoneCheck {
    /// `/health/detail` showed the spawn and its group gone.
    Gone,
    /// Read until [`REJECT_GONE_WITHIN`] was up, never showing it gone.
    NotSeenGone,
    /// No read was made, for this reason.
    Unread(String),
}

/// The `vm terminate` hint for `what` (a spawn) on `vm`, not seen gone after
/// a refused credential's stop. It says only what the child-gone check did:
/// it read for its time, it made no read (and why), or a signal ended it
/// first (`looked` is `None`).
fn not_seen_gone_line(what: &str, vm: &str, looked: Option<&GoneCheck>) -> String {
    let fix = format!("`ai-env vm terminate {vm}` ends it");
    match looked {
        Some(GoneCheck::Unread(why)) => format!("ai-env: {what} was not seen gone from {vm}: the check made no read ({why}); it holds the refused token: {fix}"),
        Some(_) => format!("ai-env: {what} was not seen gone from {vm} within {} s (it holds the refused token): {fix}", REJECT_GONE_WITHIN.as_secs()),
        None => format!("ai-env: {what} was not seen gone from {vm} before a signal ended the check (it holds the refused token): {fix}"),
    }
}

/// Spawn `id` is gone from what `/health/detail` lists: not listed (its exit
/// was collected, or the shim released it), or its leader dead and no process
/// of its group left (`group_alive`).
fn gone_from(spawns: &[crate::wire::frame::SpawnDetail], id: &SpawnId) -> bool {
    spawns.iter().find(|s| s.status.spawn_id == *id).is_none_or(|s| !s.status.alive && !s.group_alive)
}

/// The session's own failure as the command's error (a gap names the way
/// out). A command the VM could not start exits like a shell's: 127 when the
/// program does not exist, 126 when it cannot be run (the reason on `err`,
/// in order with the remote's stderr); a working directory that cannot be
/// made is ai-env's exit 1; the shim's limit of live spawns on `vm` is a
/// refusal (9), never the "VM lost" 8.
fn session_error(e: BridgeError, err: &Writer, vm: &str) -> CliError {
    match e {
        BridgeError::Gap { spawn_id, from_seq } => {
            CliError::VmLost(format!("spawn {spawn_id} no longer holds its stdout from seq {from_seq}: that output was acknowledged and trimmed (attach without --from-seq to replay what it still holds)"))
        }
        BridgeError::SpawnRefused { code, message } => match code {
            "not_found" | "exec" => {
                err.line(format!("ai-env: vm exec: {message}"));
                CliError::Exit(if code == "not_found" { NOT_FOUND_STATUS } else { NOT_EXECUTABLE_STATUS })
            }
            "limit" => {
                tracing::info!("vm {vm}: the shim refused the spawn: {message}");
                BridgeError::Policy(format!("{vm} already runs {MAX_SPAWNS} commands, the most its shim allows: wait for one to end (`ai-env vm health {vm} --detail` lists them)")).into()
            }
            _ => CliError::Msg(format!("vm exec: {message}")),
        },
        e => e.into(),
    }
}

/// A program the VM does not have, or cannot run: a shell's statuses.
const NOT_FOUND_STATUS: i32 = 127;
const NOT_EXECUTABLE_STATUS: i32 = 126;

/// Resolves at `t`; never when `None` (a select arm that stays quiet).
async fn at(t: Option<tokio::time::Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// stdin in `CHUNK_MAX` pieces until EOF (or the session is gone).
fn read_stdin(input: &mpsc::Sender<SpawnInput>) {
    let mut stdin = std::io::stdin().lock();
    let mut buf = vec![0u8; CHUNK_MAX];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if input.blocking_send(SpawnInput::Stdin(buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                tracing::warn!("vm exec: reading stdin failed ({e}); closing the remote's stdin");
                break;
            }
        }
    }
    let _ = input.blocking_send(SpawnInput::StdinEof);
}

/// What the event loop knows of the attachment.
struct View {
    vm: String,
    spawn: Option<SpawnId>,
    /// A socket carries the spawn (from `Started` on, as the session's notes
    /// tell it): what the pump sends now reaches the VM.
    linked: bool,
    /// `vm exec` got a signal before the spawn ran: it is giving the attachment up.
    given_up: bool,
    /// The `ai-env: spawn …` line goes to stderr only on a terminal (always to the log).
    show_spawn: bool,
    dropped: Dropped,
    /// S7 D6: the refused-credential watch over a credentialed `claude`.
    watch: Option<AuthWatch>,
    /// The watch said the credential was refused.
    rejected: bool,
}

impl View {
    fn new(vm: &str) -> View {
        View { vm: vm.to_string(), spawn: None, linked: false, given_up: false, show_spawn: std::io::stderr().is_terminal(), dropped: Dropped::default(), watch: None, rejected: false }
    }

    fn event(&mut self, ev: SpawnEvent, out: &Writer, err: &Writer) {
        match ev {
            SpawnEvent::Started { spawn_id, pid, pgid, .. } => {
                let line = format!("spawn {spawn_id} pid {pid} on {} (reattach: ai-env vm attach {} --spawn {spawn_id})", self.vm, self.vm);
                tracing::info!("vm {}: {line} (pgid {pgid})", self.vm);
                if self.show_spawn {
                    err.line(format!("ai-env: {line}"));
                }
                if self.given_up && self.spawn.is_none() {
                    err.line(format!("ai-env: the command started on {} before the signal reached it: it gets the signal, then `detach final` (the VM stops it)", self.vm));
                }
                self.spawn = Some(spawn_id);
                self.linked = true;
            }
            SpawnEvent::Stdout { seq, bytes } => {
                self.watch_chunk(WatchStream::Stdout, &bytes);
                out.chunk(seq, bytes);
            }
            SpawnEvent::Stderr { seq, bytes, dropped } => {
                if let Some(n) = self.dropped.chunk(dropped, Instant::now()) {
                    note_dropped(err, n);
                }
                self.watch_chunk(WatchStream::Stderr, &bytes);
                err.chunk(seq, bytes);
            }
            SpawnEvent::Note(text) => err.line(format!("ai-env: {text}")),
            SpawnEvent::Link(up) => self.linked = up,
            SpawnEvent::Exit(exit) => {
                if let Some(n) = self.dropped.exit(exit.stderr_dropped, Instant::now()) {
                    note_dropped(err, n);
                }
                if exit.stdout_truncated {
                    err.line("ai-env: the remote's stdout was cut short: a process it left behind held the pipe open after it exited".into());
                }
            }
        }
    }

    /// Show the watch what the command printed (the bytes go on unchanged).
    fn watch_chunk(&mut self, stream: WatchStream, bytes: &[u8]) {
        if let Some(w) = &mut self.watch {
            if w.feed(stream, bytes) == Verdict::Rejected {
                self.rejected = true;
            }
        }
    }

    /// The timer of [`Dropped::due`]: say the drop the once-a-second limit held back.
    fn held_dropped(&mut self, err: &Writer) {
        if let Some(n) = self.dropped.held(Instant::now()) {
            note_dropped(err, n);
        }
    }
}

fn note_dropped(err: &Writer, n: u64) {
    err.line(format!("ai-env: {n} bytes of the remote's stderr dropped so far (it wrote faster than stderr was read)"));
}

/// `d` as the session writes it in its notes.
fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

/// When the remote's stderr drops are said: the first increase at once, a
/// later one at most once per [`DROPPED_NOTE_EVERY`] — when no stderr chunk
/// comes, by a timer at [`Dropped::due`] — and the total at the exit.
#[derive(Debug, Default)]
struct Dropped {
    seen: u64,
    said: u64,
    said_at: Option<Instant>,
}

impl Dropped {
    /// A stderr chunk's cumulative count at `now`: the count to say now, if any.
    fn chunk(&mut self, dropped: u64, now: Instant) -> Option<u64> {
        self.seen = self.seen.max(dropped);
        let free = self.said_at.is_none_or(|t| now.saturating_duration_since(t) >= DROPPED_NOTE_EVERY);
        if free {
            self.held(now)
        } else {
            None
        }
    }

    /// When an increase the limit held back is due (`None`: nothing is held back).
    fn due(&self) -> Option<Instant> {
        self.said_at.filter(|_| self.seen > self.said).map(|t| t + DROPPED_NOTE_EVERY)
    }

    /// What is not said yet (the timer, and the exit after [`Dropped::exit`]'s count).
    fn held(&mut self, now: Instant) -> Option<u64> {
        if self.seen <= self.said {
            return None;
        }
        self.said = self.seen;
        self.said_at = Some(now);
        Some(self.seen)
    }

    /// The exit's total, unless it was said already.
    fn exit(&mut self, dropped: u64, now: Instant) -> Option<u64> {
        self.seen = self.seen.max(dropped);
        self.held(now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

/// What a writer thread writes: a chunk (marked consumed once written and flushed) or a line of ai-env's own.
enum Piece {
    Chunk(u64, Vec<u8>),
    Line(String),
}

/// One output stream's thread: writes and flushes each piece in order, then
/// marks its seq in `Consumed`. After a failed write it writes nothing more
/// (still marking, so the session is never held up), and `broken` hears of
/// the failure once.
struct Writer {
    tx: std::sync::mpsc::Sender<Piece>,
    thread: std::thread::JoinHandle<()>,
}

impl Writer {
    fn start(stream: Stream, consumed: Arc<Consumed>, broken: Option<mpsc::UnboundedSender<std::io::Error>>) -> Result<Writer> {
        let (tx, rx) = std::sync::mpsc::channel::<Piece>();
        let name = if stream == Stream::Stdout { "vm-exec-stdout" } else { "vm-exec-stderr" };
        let thread = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let mut failed = false;
                for piece in rx {
                    let (seq, bytes) = match piece {
                        Piece::Chunk(seq, bytes) => (Some(seq), bytes),
                        Piece::Line(mut line) => {
                            line.push('\n');
                            (None, line.into_bytes())
                        }
                    };
                    if !failed {
                        if let Err(e) = write_flush(stream, &bytes) {
                            failed = true;
                            if let Some(b) = &broken {
                                let _ = b.send(e);
                            }
                        }
                    }
                    match (seq, stream) {
                        (Some(seq), Stream::Stdout) => consumed.stdout_done(seq),
                        (Some(seq), Stream::Stderr) => consumed.stderr_done(seq),
                        (None, _) => {}
                    }
                }
            })
            .map_err(|e| CliError::Msg(format!("cannot start the {name} writer: {e}")))?;
        Ok(Writer { tx, thread })
    }

    fn chunk(&self, seq: u64, bytes: Vec<u8>) {
        let _ = self.tx.send(Piece::Chunk(seq, bytes));
    }

    fn line(&self, line: String) {
        let _ = self.tx.send(Piece::Line(line));
    }

    /// Everything sent so far is written (or its stream failed).
    fn close(self) {
        drop(self.tx);
        let _ = self.thread.join();
    }
}

fn write_flush(stream: Stream, bytes: &[u8]) -> std::io::Result<()> {
    match stream {
        Stream::Stdout => {
            let mut out = std::io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()
        }
        Stream::Stderr => {
            let mut err = std::io::stderr().lock();
            err.write_all(bytes)?;
            err.flush()
        }
    }
}

// ---- vm health --detail ------------------------------------------------------------

/// `vm health --detail`: a 5-minute `Port(8080)` token and the row's session
/// bearer on `GET /health/detail`; a human summary or `--json`.
pub async fn health_detail<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, id: &str, row: &VmRow, json: bool) -> Result<()> {
    let vm = live_vm(api, id).await?;
    let endpoint = Some(vm.endpoint.clone()).filter(|e| !e.is_empty()).or_else(|| row.endpoint.clone()).unwrap_or_default();
    let bearer = Secret::new(row.session_token.clone().unwrap_or_default());
    crate::wire::redact::register_secret(bearer.expose());
    let token = crate::bridge::vm::token::mint_internal(api, &ctx.paths, id).await?;
    let reply = ep.get_health_detail(&endpoint, &token, &bearer).await?;
    let detail = match (reply.status, reply.proxy_error, reply.detail) {
        (200, _, Some(d)) => d,
        (200, _, None) => return Err(BridgeError::Http { status: 200, body: "no /health/detail body".into() }.into()),
        (status @ (401 | 403), Some(proxy_error), _) => return Err(BridgeError::TokenRejected { port: token.port, status, proxy_error: Some(proxy_error) }.into()),
        (401, None, _) => return Err(CliError::Aws(format!("{id}: the VM refused this Mac's session bearer (stale row?): HTTP 401 on /health/detail"))),
        (status, proxy_error, _) => {
            let mut body = proxy_error.map(|p| format!("x-aws-proxy-error: {p}")).unwrap_or_default();
            if !reply.body.is_empty() {
                body = if body.is_empty() { reply.body } else { format!("{body}; {}", reply.body) };
            }
            return Err(BridgeError::Http { status, body }.into());
        }
    };
    // S7: what this Mac's row says the VM received, beside what its shim says it caches now.
    let received = row.credential_at.map(|at| (crate::wire::time::rfc3339_utc(at), row.credential_tag.clone()));
    if json {
        let row_view = serde_json::json!({ "credential_at": received.as_ref().map(|(at, _)| at), "credential_tag": received.as_ref().and_then(|(_, tag)| tag.as_ref()) });
        let v = serde_json::json!({ "backend": ctx.backend_name(), "id": id, "detail": detail, "row": row_view });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
        return Ok(());
    }
    for line in detail_lines(&detail, received.as_ref().map(|(at, tag)| (at.as_str(), tag.as_deref()))) {
        outln!("{line}");
    }
    Ok(())
}

/// The human summary of `/health/detail`; `received`: when this Mac's row
/// says a token was last sent to the VM, and its seal (S7: the setup-token's,
/// or a `--credential-file` one-shot's own).
fn detail_lines(d: &HealthDetail, received: Option<(&str, Option<&str>)>) -> Vec<String> {
    let h = &d.health;
    let yes = |b: bool| if b { "yes" } else { "no" };
    let mut out = vec![format!(
        "{} shim {} claude {} image {} run_hook_seen {} uptime {} s",
        serde_json::to_value(h.status).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
        h.shim_version,
        h.claude_version.as_deref().unwrap_or("-"),
        d.image_version.as_deref().unwrap_or("-"),
        yes(h.run_hook_seen),
        h.uptime_s
    )];
    let refused = if d.refused_peers.is_empty() { "none".to_string() } else { d.refused_peers.iter().map(|(port, n)| format!("{port}={n}")).collect::<Vec<_>>().join(" ") };
    out.push(format!("  guard      hook_source {}, agent_guard {}; refused peers: {refused}", d.hook_source, d.agent_guard));
    out.push(format!("  sockets    {} open, {} authenticated", d.sockets_open, d.sockets_authenticated));
    let peers = |m: &BTreeMap<String, HookPeerSeen>| {
        if m.is_empty() {
            return "none".to_string();
        }
        let opt = |v: Option<String>| v.unwrap_or_else(|| "-".into());
        m.iter().map(|(hook, p)| format!("{hook} {} uid {} ino {} from {} at {}", p.decision, opt(p.uid.map(|u| u.to_string())), opt(p.inode.map(|i| i.to_string())), p.peer, p.at)).collect::<Vec<_>>().join("; ")
    };
    out.push(format!("  hooks      {}", peers(&d.hook_peers)));
    out.push(format!("  refusals   {}", peers(&d.hook_refusals)));
    if d.spawns.is_empty() {
        out.push("  spawns     none".into());
    } else {
        out.push(format!("  {:<36} {:<12} {:>7} {:<5} {:<8} {:>13} {:>7} {:>7} EXIT", "SPAWN", "ARGV0", "PID", "ALIVE", "ATTACHED", "OUT(FROM..SEQ)", "ERR", "IN"));
        for s in &d.spawns {
            let st = &s.status;
            let exit = st.exit.map_or_else(|| "-".to_string(), |e| e.code.map_or_else(|| e.signal.map_or_else(|| "?".to_string(), |n| format!("signal {n}")), |c| format!("code {c}")));
            let argv0: String = st.argv0.chars().take(12).collect();
            // `alive` is the leader alone: a group that outlived it (S7 D6, what
            // the child-gone check and its `vm terminate` hint are about) is `group`.
            let alive = if st.alive { "yes" } else if s.group_alive { "group" } else { "no" };
            out.push(format!("  {:<36} {argv0:<12} {:>7} {:<5} {:<8} {:>13} {:>7} {:>7} {exit}", st.spawn_id, st.pid, alive, yes(st.attached), format!("{}..{}", st.out_from, st.out_seq), st.err_seq, st.in_seq));
        }
        if d.spawns.iter().any(|s| !s.status.alive && s.group_alive) {
            out.push("  (ALIVE group: the leader exited, but a process of its group still runs, with whatever the command was handed)".into());
        }
    }
    let more = if d.listeners_omitted > 0 { format!("; {} more not listed", d.listeners_omitted) } else { String::new() };
    out.push(format!("  listeners  {} ({} the shim's own{more})", d.listeners.len(), d.listeners.iter().filter(|l| l.own).count()));
    // One row each, as in-vm-firewall's note names them (a `listeners` gap is investigated here).
    for l in &d.listeners {
        let at = if l.addr.contains(':') { format!("[{}]:{}", l.addr, l.port) } else { format!("{}:{}", l.addr, l.port) };
        out.push(format!("             {at} uid {} inode {}{}", l.uid, l.inode, if l.own { " own" } else { "" }));
    }
    // S7: the cache, and the commands handed a secret, which keep their copy
    // (as does any snapshot taken while they run) whatever the cache says.
    let c = &d.credential;
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
    let cache = if d.has_credentials { format!("yes: {} cached (seal {}, at {})", opt(&c.credential_name), opt(&c.credential_tag), opt(&c.credential_at)) } else { "no copy cached".to_string() };
    let held = match c.credential_holders {
        0 => String::new(),
        1 => "; 1 running command was handed a secret: it, and any snapshot taken while it runs, holds it until the VM is terminated".to_string(),
        n => format!("; {n} running commands were handed a secret: they, and any snapshot taken while they run, hold it until the VM is terminated"),
    };
    // What the shim caches now is not all the VM may hold: this Mac's row names when a token last left for it
    // (the setup-token, or a `--credential-file` one-shot's, whose seal is its own file's).
    let row = received.map_or_else(String::new, |(at, tag)| format!("; this Mac's row: a token was last sent to it{} at {at}", tag.map(|t| format!(" (seal {t})")).unwrap_or_default()));
    out.push(format!("  credentials {cache}{held}{row}"));
    let clock = d.clock.as_ref().map_or_else(
        || "no report yet".to_string(),
        |c| {
            let field = |k: &str| c.get(k).map_or_else(|| "-".to_string(), |v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
            format!("last report on {} (drift {} s, mode {})", field("hook"), field("drift_s"), field("mode"))
        },
    );
    out.push(format!("  clock      {clock}"));
    out
}

// ---- vm smoke --exec ---------------------------------------------------------------

/// One `vm smoke --exec` step: its record field, what the command printed
/// (trimmed; `None` when it could not run), whether that is what was expected,
/// and the step line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeStep {
    pub field: &'static str,
    pub got: Option<String>,
    pub ok: bool,
    pub line: String,
}

/// What `vm smoke --exec` ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmokeExec {
    pub steps: Vec<SmokeStep>,
    pub ms: u64,
}

impl SmokeExec {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok)
    }

    /// The failed steps, one line each.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        self.steps.iter().filter(|s| !s.ok).map(|s| s.line.clone()).collect()
    }

    /// The record's `exec_*` fields.
    pub fn record(&self, rec: &mut serde_json::Map<String, serde_json::Value>) {
        for s in &self.steps {
            rec.insert(s.field.into(), s.got.clone().into());
        }
        rec.insert("exec_ok".into(), self.ok().into());
        rec.insert("exec_ms".into(), self.ms.into());
        rec.insert("exec_problems".into(), self.problems().into());
    }
}

/// What one in-memory consumer saw.
#[derive(Debug, Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: i32,
}

/// Run `spec` with an empty stdin and keep what it prints (each stream capped at [`CAPTURE_MAX`]).
async fn capture<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, spec: SpawnSpec, delivery: Option<Delivery>) -> std::result::Result<Captured, BridgeError> {
    let (io, c) = spawn_channels(1);
    let ConsumerIo { input, control, mut events, consumed } = c;
    let _ = input.try_send(SpawnInput::StdinEof);
    drop(input);
    let keep = |into: &mut Vec<u8>, bytes: &[u8]| into.extend_from_slice(&bytes[..bytes.len().min(CAPTURE_MAX.saturating_sub(into.len()))]);
    let read = async move {
        let mut cap = Captured::default();
        while let Some(ev) = events.recv().await {
            match ev {
                SpawnEvent::Stdout { seq, bytes } => {
                    keep(&mut cap.stdout, &bytes);
                    consumed.stdout_done(seq);
                }
                SpawnEvent::Stderr { seq, bytes, .. } => {
                    keep(&mut cap.stderr, &bytes);
                    consumed.stderr_done(seq);
                }
                SpawnEvent::Started { .. } | SpawnEvent::Note(_) | SpawnEvent::Link(_) | SpawnEvent::Exit(_) => {}
            }
        }
        cap
    };
    let run = tokio::time::timeout(SMOKE_STEP_LIMIT, run_spawn_with(env, Start::New(spec), io, delivery));
    let (outcome, cap) = tokio::join!(run, read);
    drop(control);
    match outcome {
        Ok(Ok(o)) => Ok(Captured { status: o.exit.status(), ..cap }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(BridgeError::Transport(format!("no exit within {} s", SMOKE_STEP_LIMIT.as_secs()))),
    }
}

/// A version line `claude --version` prints: `<x.y.z> (Claude Code)`.
fn is_claude_version_line(line: &str) -> bool {
    line.strip_suffix(" (Claude Code)").is_some_and(|v| {
        let parts: Vec<&str> = v.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// What a smoke step must print.
#[derive(Debug, PartialEq, Eq)]
enum Want {
    Exactly(String),
    /// Any `<x.y.z> (Claude Code)` (no lock version recorded to compare with).
    ClaudeVersion,
}

impl Want {
    fn matches(&self, got: &str) -> bool {
        match self {
            Want::Exactly(w) => got == w,
            Want::ClaudeVersion => is_claude_version_line(got),
        }
    }

    fn shown(&self) -> &str {
        match self {
            Want::Exactly(w) => w,
            Want::ClaudeVersion => "<x.y.z> (Claude Code)",
        }
    }
}

/// `vm smoke --exec`'s steps for row `row`, each with its record field and
/// what it must print: `claude --version` (`expected_claude` is the image
/// lock's version when recorded), `id -u`, and on vpc rows the API through
/// the proxy (401: no key, but the tunnel reached it) and the proxy variables.
fn smoke_plan(row: &VmRow, expected_claude: Option<&str>) -> Vec<(&'static str, Vec<&'static str>, Want)> {
    let claude = expected_claude.map_or(Want::ClaudeVersion, |v| Want::Exactly(format!("{v} (Claude Code)")));
    let mut plan = vec![("exec_claude", vec!["claude", "--version"], claude), ("exec_uid", vec!["id", "-u"], Want::Exactly("1000".into()))];
    if row.egress == "vpc" {
        // Bounded: a proxy that does not answer fails this step in seconds, not at the step limit.
        plan.push(("exec_curl", vec!["curl", "-sS", "--connect-timeout", "10", "--max-time", "30", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com/v1/models"], Want::Exactly("401".into())));
        plan.push(("exec_proxy_vars", vec!["sh", "-c", "env | grep -ci _proxy"], Want::Exactly("6".into())));
    }
    plan
}

/// A step's command as its line shows it (an argument with a space quoted).
fn command_line(argv: &[&str]) -> String {
    argv.iter().map(|a| if a.contains(' ') { format!("'{a}'") } else { (*a).to_string() }).collect::<Vec<_>>().join(" ")
}

/// A step whose command ran (`cap`, in `ms`): ok when it exited 0 printing
/// what `want` says (trimmed); the line says what it printed, and the first
/// line of its stderr when it exited otherwise.
fn judged(field: &'static str, shown: &str, want: &Want, cap: &Captured, ms: u128) -> SmokeStep {
    let got = String::from_utf8_lossy(&cap.stdout).trim().chars().take(200).collect::<String>();
    let ok = cap.status == 0 && want.matches(&got);
    let mut line = format!("exec {shown} → {got:?} in {ms} ms (expected {:?}, exit {})", want.shown(), cap.status);
    if cap.status != 0 {
        let first = String::from_utf8_lossy(&cap.stderr).lines().next().unwrap_or_default().chars().take(200).collect::<String>();
        if !first.is_empty() {
            line.push_str(&format!(": {}", scrub(&first)));
        }
    }
    line.push_str(if ok { ": ok" } else { ": MISMATCH" });
    SmokeStep { field, got: Some(got), ok, line }
}

/// `vm smoke --exec`'s steps ([`smoke_plan`]) on the smoke's VM (row `row`).
/// A step that cannot run ends the steps (the rest are not run).
pub async fn smoke_exec<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, expected_claude: Option<&str>) -> SmokeExec {
    let started = Instant::now();
    let env = agent_env(ctx, api, ep, row, None).map_err(|e| e.to_string());
    let mut steps = Vec::new();
    let mut broken: Option<String> = None;
    for (field, argv, want) in smoke_plan(row, expected_claude) {
        let shown = command_line(&argv);
        let env = match (&env, &broken) {
            (Err(e), _) | (_, Some(e)) => {
                steps.push(SmokeStep { field, got: None, ok: false, line: format!("exec {shown}: not run ({e})") });
                continue;
            }
            (Ok(env), None) => env,
        };
        let spec = SpawnSpec { argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: spawn_env(ctx, row, &[]), detach_grace_s: None };
        let t = Instant::now();
        match capture(env, spec, None).await {
            Ok(cap) => steps.push(judged(field, &shown, &want, &cap, t.elapsed().as_millis())),
            Err(e) => {
                let why = e.to_string();
                steps.push(SmokeStep { field, got: None, ok: false, line: format!("exec {shown}: {why}") });
                broken = Some(why);
            }
        }
    }
    SmokeExec { steps, ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX) }
}

/// What `vm smoke --with-credential`'s credential step came to (S7). Its
/// record keeps flags and the token's source, never the answer's text or
/// anything of the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeCred {
    pub ok: bool,
    /// The step line (`ai-env vm smoke` prints it like the exec steps).
    pub line: String,
    pub problem: Option<String>,
    pub ms: u64,
    /// The result's `is_error`, when a result came back.
    pub is_error: Option<bool>,
    /// Where the token came from (`credential::Prepared::source`), or `none`.
    pub source: &'static str,
}

impl SmokeCred {
    /// Into the smoke record: `cred_ok`, `cred_ms`, `cred_is_error`,
    /// `cred_token`; a failure also makes `exec_ok` false and joins
    /// `exec_problems`, so the smoke's verdict fails.
    pub fn record(&self, rec: &mut serde_json::Map<String, serde_json::Value>) {
        rec.insert("cred_ok".into(), self.ok.into());
        rec.insert("cred_ms".into(), self.ms.into());
        rec.insert("cred_is_error".into(), self.is_error.map_or(serde_json::Value::Null, Into::into));
        rec.insert("cred_token".into(), self.source.into());
        if let Some(p) = &self.problem {
            rec.insert("exec_ok".into(), false.into());
            let mut problems = rec.get("exec_problems").and_then(serde_json::Value::as_array).cloned().unwrap_or_default();
            problems.push(p.clone().into());
            rec.insert("exec_problems".into(), problems.into());
        }
    }
}

/// The JSON `claude -p --output-format json` printed (its last object
/// line): `is_error`, and whether `result` answers OK.
fn claude_result(stdout: &[u8]) -> Option<(bool, bool)> {
    let text = String::from_utf8_lossy(stdout);
    let v = text.lines().rev().filter(|l| l.trim_start().starts_with('{')).find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())?;
    let is_error = v.get("is_error")?.as_bool()?;
    let ok = v.get("result").and_then(serde_json::Value::as_str).is_some_and(|r| r.trim().to_ascii_uppercase().starts_with("OK"));
    Some((is_error, ok))
}

/// `vm smoke --with-credential` (S7): the credential's checks, gate, token
/// and delivery on the smoke's VM, then `claude -p 'Reply OK' --output-format
/// json` with it. `ok` when the command exits 0 and its result answers OK
/// without `is_error`; a refused token (S7 D6, `vm exec`'s watch) fails it
/// and is recorded against its seal, as `vm exec` records it.
pub async fn smoke_credential<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, supply: CredentialSupply<'_>) -> SmokeCred {
    let started = Instant::now();
    let argv = ["claude", "-p", "Reply OK", "--output-format", "json"];
    let shown = command_line(&argv);
    let argv: Vec<String> = argv.iter().map(|a| (*a).to_string()).collect();
    let ran = async {
        let flags = CredentialFlags { with_credential: true, ..CredentialFlags::default() };
        let plan = super::credential::check(&ctx.cfg, &ctx.paths, row, &argv, &flags)?.ok_or_else(|| CliError::Msg("internal: no credential plan".into()))?;
        let prepared = super::credential::prepare(ctx, api, ep, row, vm, &plan, supply).await?;
        let env = agent_env(ctx, api, ep, row, Some(vm))?;
        let spec = SpawnSpec { argv: argv.clone(), cwd: None, env: spawn_env(ctx, row, &[]), detach_grace_s: None };
        let cap = capture(&env, spec, Some(prepared.delivery)).await?;
        Ok::<_, CliError>((cap, prepared.source, plan.tag))
    }
    .await;
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match ran {
        Ok((cap, source, tag)) => {
            // S7 D6: `vm exec`'s watch over what this claude printed (it ran
            // to its end: nothing to stop); a refusal is recorded as there.
            let mut watch = AuthWatch::new();
            watch.feed(WatchStream::Stdout, &cap.stdout);
            watch.feed(WatchStream::Stderr, &cap.stderr);
            let refused = watch.rejected_at_exit(Some(cap.status)).then(|| if watch.retries() >= RETRY_LIMIT { "retries" } else { "text" });
            if let Some(how) = refused {
                super::credential::record_rejection(&ctx.paths, &row.id, &tag, how);
            }
            let result = claude_result(&cap.stdout);
            let ok = refused.is_none() && cap.status == 0 && result == Some((false, true));
            let said = match result {
                Some((false, true)) => "answered OK".to_string(),
                Some((false, false)) => "answered something else".to_string(),
                Some((true, _)) => "is_error true".to_string(),
                None => "no JSON result".to_string(),
            };
            let said = if refused.is_some() { "Anthropic refused the delivered setup-token (HTTP 401), which is recorded: credentialed commands refuse it until `ai-env creds setup-token` seals a fresh one".to_string() } else { said };
            let line = format!("exec {shown} (credential: {source}): exit {}, {said} ({ms} ms)", cap.status);
            SmokeCred { ok, problem: (!ok).then(|| line.clone()), line, ms, is_error: result.map(|r| r.0), source }
        }
        Err(e) => {
            let line = format!("exec {shown} (credential): {e}");
            SmokeCred { ok: false, problem: Some(line.clone()), line, ms, is_error: None, source: "none" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::config::{BridgeConfig, Paths};
    use crate::bridge::lab::VmKnobs;
    use crate::bridge::vm::registry::write_row;

    const ID: &str = "microvm-00000000-0000-4000-8000-0000000000e1";

    fn ctx(dir: &std::path::Path) -> Ctx {
        Ctx { paths: Paths::from_root_and_env(dir.to_path_buf(), None), cfg: BridgeConfig::default(), knobs: VmKnobs::default() }
    }

    /// A row as `vm run` leaves it, with a session token built at runtime.
    fn row(egress: &str) -> VmRow {
        VmRow { id: ID.into(), status: RowStatus::Running, egress: egress.into(), session_token: Some("s".repeat(40)), endpoint: Some("ffffffff-0000-4000-8000-000000000001.lambda-microvm.eu-central-1.on.aws".into()), ..VmRow::default() }
    }

    fn exec(c: &Ctx, env: &[&str], argv: &[&str]) -> Result<ExecPlan> {
        check_exec(c, ID, None, &env.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(), None, argv.iter().map(|s| (*s).to_string()).collect(), &CredentialFlags::default())
    }

    #[test]
    fn flags_are_usage_errors_before_the_row_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let code = |r: Result<ExecPlan>| r.unwrap_err().exit_code();
        assert_eq!(code(check_exec(&c, "bad/id", None, &[], None, vec!["true".into()], &CredentialFlags::default())), 2);
        assert_eq!(code(exec(&c, &[], &[])), 2, "empty argv");
        assert_eq!(code(exec(&c, &[], &[""])), 2, "empty argv[0]");
        let long = "x".repeat(ARGV_MAX_BYTES);
        assert_eq!(code(exec(&c, &[], &["echo", &long])), 2);
        for bad in ["relative/dir", "/a/../b", "/a/./b", "."] {
            assert_eq!(code(check_exec(&c, ID, Some(bad.into()), &[], None, vec!["true".into()], &CredentialFlags::default())), 2, "{bad}");
        }
        assert_eq!(code(exec(&c, &["NOEQUALS"], &["true"])), 2);
        assert_eq!(code(exec(&c, &["9LIVES=x", "OK=1"], &["true"])), 2);
        assert_eq!(code(exec(&c, &["A=1", "A=2"], &["true"])), 2);
        let many: Vec<String> = (0..=ENV_MAX_ENTRIES).map(|i| format!("V{i}=x")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(code(exec(&c, &many, &["true"])), 2);
        assert_eq!(code(exec(&c, &["LANG=C"], &["true"])), 1, "valid flags, then no row: exit 1");
    }

    #[test]
    fn usage_errors_never_echo_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        for env in ["private-value-without-a-name", "BAD-NAME=private-value-2", "AWS_PROFILE=private-value-3", "my_token=private-value-4"] {
            let e = exec(&c, &[env], &["true"]).unwrap_err().to_string();
            assert!(!e.contains("private-value"), "{e}");
        }
    }

    #[test]
    fn refused_names_are_policy_in_any_case() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        for name in ["CLAUDECODE", "claudecode", "NODE_OPTIONS", "AWS_REGION", "aws_profile", "Aws_X", "GITHUB_TOKEN", "api_key", "MonkeyBusiness", "DB_SECRET", "PASSWORD", "HOME", "Path", "CLAUDE_CONFIG_DIR"] {
            let e = exec(&c, &[&format!("{name}=v")], &["true"]).unwrap_err();
            assert_eq!(e.exit_code(), 9, "{name}: {e}");
            assert!(e.to_string().contains(name), "names the variable: {e}");
        }
        assert!(refused_name("LANG").is_none() && refused_name("https_proxy").is_none() && refused_name("TERM").is_none());
    }

    #[test]
    fn the_row_decides_after_the_flags() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        assert_eq!(exec(&c, &[], &["true"]).unwrap_err().exit_code(), 1, "no row");
        write_row(&c.paths, &VmRow { session_token: None, ..row("internet") }).unwrap();
        let e = exec(&c, &[], &["true"]).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("no session token"), "{e}");
        write_row(&c.paths, &VmRow { shell: true, ..row("internet") }).unwrap();
        let e = exec(&c, &[], &["true"]).unwrap_err();
        assert!(e.exit_code() == 9 && e.to_string().contains("in-vm-firewall") && e.to_string().contains("without --shell"), "{e}");
        write_row(&c.paths, &VmRow { status: RowStatus::Terminated, terminated_by: Some("operator".into()), ..row("internet") }).unwrap();
        assert_eq!(exec(&c, &[], &["true"]).unwrap_err().exit_code(), 8);
        write_row(&c.paths, &row("internet")).unwrap();
        let plan = exec(&c, &["https_proxy=http://10.0.0.9:3128", "LANG=C"], &["/usr/bin/env", "--private-arg"]).unwrap();
        assert_eq!(plan.env.len(), 2, "proxy names are the operator's on internet rows");
        write_row(&c.paths, &row("vpc")).unwrap();
        for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY", "No_Proxy"] {
            let e = exec(&c, &[&format!("{name}=x")], &["true"]).unwrap_err();
            assert_eq!(e.exit_code(), 9, "{name}: {e}");
        }
        let shown = format!("{plan:?}");
        assert!(shown.contains("argv0=env") && shown.contains("argc=2") && shown.contains("env=2"), "{shown}");
        for leak in ["--private-arg", "10.0.0.9", "ssssssss"] {
            assert!(!shown.contains(leak), "{leak}: {shown}");
        }
    }

    #[test]
    fn attach_and_detail_checks() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let spawn = SpawnId::new_v7().0;
        assert_eq!(check_attach(&c, ID, "not-a-uuid", None).unwrap_err().exit_code(), 2);
        assert_eq!(check_attach(&c, ID, "0192f1e0-2b7c-4c3a-9a1b-4d5e6f708192", None).unwrap_err().exit_code(), 2, "v7 only");
        assert_eq!(check_attach(&c, ID, &spawn, Some(0)).unwrap_err().exit_code(), 2);
        assert_eq!(check_attach(&c, ID, &spawn, None).unwrap_err().exit_code(), 1);
        assert_eq!(check_detail(&c, ID).unwrap_err().exit_code(), 1);
        assert_eq!(check_detail(&c, "../x").unwrap_err().exit_code(), 2);
        write_row(&c.paths, &VmRow { shell: true, ..row("internet") }).unwrap();
        assert_eq!(check_attach(&c, ID, &spawn, Some(1)).unwrap_err().exit_code(), 9);
        assert!(check_detail(&c, ID).is_ok(), "a --shell row may read /health/detail");
        write_row(&c.paths, &row("internet")).unwrap();
        let plan = check_attach(&c, ID, &spawn, Some(3)).unwrap();
        assert_eq!(format!("{plan:?}"), format!("AttachPlan({ID}, spawn={spawn}, from_seq=Some(3))"));
    }

    #[test]
    fn a_spawn_frame_over_the_control_cap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        write_row(&c.paths, &row("internet")).unwrap();
        // Control bytes escape to six characters each: a 1 MiB argv can make a frame over 4 MiB.
        let arg = "\u{1}".repeat(ARGV_MAX_BYTES - 16);
        assert_eq!(exec(&c, &[], &["printf", &arg]).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn the_vpc_spawn_env_puts_the_proxy_first_and_the_operators_pairs_after() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let env = spawn_env(&c, &row("vpc"), &[("LANG".into(), "C".into())]);
        assert_eq!(env.len(), 7);
        assert_eq!(env["https_proxy"], format!("http://{}:3128", crate::bridge::egress::PROXY_IP));
        assert_eq!(env["NO_PROXY"], "localhost,127.0.0.1,::1");
        let env = spawn_env(&c, &row("internet"), &[("LANG".into(), "C".into())]);
        assert_eq!(env.into_iter().collect::<Vec<_>>(), vec![("LANG".to_string(), "C".to_string())]);
    }

    #[test]
    fn a_stderr_drop_the_limit_held_back_is_said_by_the_timer() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut d = Dropped::default();
        assert_eq!((d.chunk(0, t0), d.due()), (None, None), "nothing dropped");
        assert_eq!(d.chunk(10, at(0)), Some(10), "the first increase is said at once");
        assert_eq!(d.chunk(10, at(50)), None, "no increase");
        assert_eq!(d.chunk(25, at(100)), None, "within the second: held back");
        assert_eq!(d.due(), Some(at(1000)), "the timer says it once the second passed");
        assert_eq!(d.held(at(1000)), Some(25));
        assert_eq!((d.due(), d.held(at(1500))), (None, None), "said once");
        assert_eq!(d.chunk(40, at(2100)), Some(40), "a chunk past the second says it at once");
        assert_eq!(d.exit(40, at(2200)), None, "the exit repeats nothing");
        assert_eq!(d.exit(55, at(2300)), Some(55), "the exit says its total");
    }

    #[test]
    fn the_operators_ending_decides_the_status() {
        assert_eq!(Ending::Term.result().unwrap(), 143);
        assert_eq!(Ending::Interrupted.result().unwrap(), 130);
        assert_eq!(Ending::Stdout(std::io::ErrorKind::BrokenPipe.into()).result().unwrap(), 0);
        assert_eq!(Ending::Stdout(std::io::Error::other("disk full")).result().unwrap_err().exit_code(), 1);
        let rejected = Ending::CredentialRejected.result().unwrap_err();
        assert!(rejected.exit_code() == 5 && !rejected.to_string().contains("was stopped"), "exit 5, claiming no stop it did not see: {rejected}");
        assert_eq!(REJECTED_STATUS, rejected.exit_code(), "a refusal, whose line stderr's writer writes, exits silently with its status (F17)");
    }

    /// F22: the `vm terminate` hint says only what the child-gone check did:
    /// read for its 5 s, made no read at all (naming why, never a time it did
    /// not look), or was ended by a signal first.
    #[test]
    fn the_vm_terminate_hint_says_what_the_check_did() {
        let line = |looked: Option<&GoneCheck>| not_seen_gone_line("spawn S", ID, looked);
        let tail = format!("(it holds the refused token): `ai-env vm terminate {ID}` ends it");
        assert_eq!(line(Some(&GoneCheck::NotSeenGone)), format!("ai-env: spawn S was not seen gone from {ID} within 5 s {tail}"));
        assert_eq!(line(None), format!("ai-env: spawn S was not seen gone from {ID} before a signal ended the check {tail}"));
        let unread = line(Some(&GoneCheck::Unread("its token could not be minted: aws conflict".into())));
        assert_eq!(unread, format!("ai-env: spawn S was not seen gone from {ID}: the check made no read (its token could not be minted: aws conflict); it holds the refused token: `ai-env vm terminate {ID}` ends it"));
        assert!(!unread.contains("within"), "{unread}");
    }

    /// S7 D6 (M20, M15): the exit-5 line of a refused credential says what
    /// was seen of the command's end and no more (stopped, a stop not seen
    /// to end, or an exit of its own); a `--credential-file` container of its
    /// own is named, with advice about it, never about the sealed setup-token.
    #[test]
    fn a_refused_credentials_line_says_only_what_was_seen() {
        let line = |end, file: Option<&str>| rejected_text(Rejected { how: "retries", end }, file.map(std::path::Path::new));
        let stopped = line(RejectedEnd::Stopped, None);
        assert!(stopped.contains("the command was stopped") && stopped.ends_with("seal a fresh one with `claude setup-token`, then `ai-env creds setup-token`"), "{stopped}");
        for (end, says) in [(RejectedEnd::Unconfirmed, "the stop was sent, but the command was not seen to end"), (RejectedEnd::Exited, "the command exited")] {
            let text = line(end, None);
            assert!(text.contains(says) && !text.contains("was stopped"), "{text}");
        }
        for end in [RejectedEnd::Stopped, RejectedEnd::Unconfirmed, RejectedEnd::Exited] {
            for file in [None, Some("/w/other.env")] {
                let text = line(end, file);
                assert!(text.starts_with("Anthropic refused the delivered setup-token") && text.contains("not started again"), "B7 and the tests match on these: {text}");
            }
            let text = line(end, Some("/w/other.env"));
            assert!(text.contains("from /w/other.env (HTTP 401)") && text.contains("the sealed setup-token is not affected") && !text.contains("ai-env creds setup-token"), "{text}");
        }
    }

    /// S7 D6: the child-gone check reads the group, not the leader: a spawn
    /// is gone once it is not listed, or its leader is dead with no process
    /// of its group left; a dead leader whose group lives on is not gone.
    #[test]
    fn a_spawn_is_gone_only_with_its_group() {
        use crate::wire::frame::{SpawnDetail, SpawnStatus};
        let id = SpawnId::new_v7();
        let detail = |alive: bool, group_alive: bool| SpawnDetail {
            status: SpawnStatus { spawn_id: id.clone(), argv0: "claude".into(), pid: 42, pgid: 42, alive, attached: false, out_seq: 3, out_from: 1, err_seq: 0, in_seq: 0, stdin_closed: true, exit: None },
            started_at: "2026-10-08T08:00:00Z".into(),
            detach_left_s: Some(0),
            frozen: false,
            group_alive,
        };
        assert!(gone_from(&[], &id), "not listed: collected or released");
        assert!(!gone_from(&[detail(true, true)], &id), "the leader runs");
        assert!(!gone_from(&[detail(false, true)], &id), "the leader died, its group lives on");
        assert!(gone_from(&[detail(false, false)], &id), "the leader and its group are dead");
        let other = SpawnDetail { status: SpawnStatus { spawn_id: SpawnId::new_v7(), ..detail(true, true).status }, ..detail(true, true) };
        assert!(gone_from(&[other], &id), "another spawn running is not this one");
    }

    #[test]
    fn the_shims_spawn_limit_is_a_refusal_naming_the_detail() {
        let err = Writer::start(Stream::Stderr, Arc::new(Consumed::default()), None).unwrap();
        let e = session_error(BridgeError::SpawnRefused { code: "limit", message: "8 spawns are running (at most 8)".into() }, &err, ID);
        assert_eq!(e.exit_code(), 9, "{e}");
        assert!(e.to_string().contains(&format!("{ID} already runs 8 commands")) && e.to_string().contains(&format!("`ai-env vm health {ID} --detail`")), "{e}");
        assert_eq!(session_error(BridgeError::SpawnRefused { code: "cwd", message: "cannot create the working directory".into() }, &err, ID).exit_code(), 1);
        assert_eq!(session_error(BridgeError::Protocol("the shim refused spawn x (exists)".into()), &err, ID).exit_code(), 8);
        err.close();
    }

    #[test]
    fn claude_version_lines() {
        assert!(is_claude_version_line("2.1.287 (Claude Code)"));
        for bad in ["2.1 (Claude Code)", "2.1.x (Claude Code)", "2.1.287", "v2.1.287 (Claude Code)", "2..1 (Claude Code)"] {
            assert!(!is_claude_version_line(bad), "{bad}");
        }
    }

    /// `claude --version` and `id -u` everywhere; a vpc row adds exactly two
    /// steps: the API through the proxy (its 401) and the proxy variables (6),
    /// whose wants take what those commands print, trimmed, and nothing else.
    #[test]
    fn a_vpc_smoke_adds_exactly_the_curl_and_proxy_variable_steps() {
        let fields = |plan: &[(&'static str, Vec<&'static str>, Want)]| plan.iter().map(|(f, ..)| *f).collect::<Vec<_>>();
        let internet = smoke_plan(&row("internet"), None);
        assert_eq!(fields(&internet), ["exec_claude", "exec_uid"]);
        assert_eq!(internet[0], ("exec_claude", vec!["claude", "--version"], Want::ClaudeVersion), "no lock version recorded: any version line");
        assert_eq!(internet[1], ("exec_uid", vec!["id", "-u"], Want::Exactly("1000".into())));
        let vpc = smoke_plan(&row("vpc"), Some("2.1.287"));
        assert_eq!(fields(&vpc), ["exec_claude", "exec_uid", "exec_curl", "exec_proxy_vars"]);
        assert_eq!(vpc[0].2, Want::Exactly("2.1.287 (Claude Code)".into()), "the lock's version");
        assert_eq!(
            vpc[2..],
            [
                ("exec_curl", vec!["curl", "-sS", "--connect-timeout", "10", "--max-time", "30", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com/v1/models"], Want::Exactly("401".into())),
                ("exec_proxy_vars", vec!["sh", "-c", "env | grep -ci _proxy"], Want::Exactly("6".into())),
            ]
        );
        let (curl, vars) = (&vpc[2].2, &vpc[3].2);
        assert!(curl.matches("401") && vars.matches("6"));
        for other in ["403", "200", "000", "4010", ""] {
            assert!(!curl.matches(other), "{other:?}");
        }
        for other in ["5", "7", "06", "0", ""] {
            assert!(!vars.matches(other), "{other:?}");
        }
    }

    /// The success path `make s6-smoke` greps for: on a vpc VM every step
    /// exits 0 printing what it wants (as the commands print it there: a
    /// newline, curl's bare code) → every step ok, and the record says
    /// `exec_ok: true`, no problems, and what each step printed.
    #[test]
    fn a_smoke_whose_steps_print_what_they_want_records_exec_ok() {
        let printed = ["2.1.287 (Claude Code)\n", "1000\n", "401", "6\n"];
        let plan = smoke_plan(&row("vpc"), Some("2.1.287"));
        assert_eq!(plan.len(), printed.len());
        let steps: Vec<SmokeStep> = plan.iter().zip(printed).map(|((field, argv, want), out)| judged(field, &command_line(argv), want, &Captured { stdout: out.into(), stderr: Vec::new(), status: 0 }, 7)).collect();
        assert_eq!(steps.iter().map(|s| s.field).collect::<Vec<_>>(), ["exec_claude", "exec_uid", "exec_curl", "exec_proxy_vars"]);
        assert!(steps.iter().all(|s| s.ok && s.line.ends_with(": ok")), "{steps:?}");
        assert_eq!(steps[2].line, "exec curl -sS --connect-timeout 10 --max-time 30 -o /dev/null -w %{http_code} https://api.anthropic.com/v1/models → \"401\" in 7 ms (expected \"401\", exit 0): ok");
        assert_eq!(steps[3].line, "exec sh -c 'env | grep -ci _proxy' → \"6\" in 7 ms (expected \"6\", exit 0): ok");
        let ran = SmokeExec { steps, ms: 42 };
        assert!(ran.ok() && ran.problems().is_empty());
        let mut rec = serde_json::Map::new();
        ran.record(&mut rec);
        let want = serde_json::json!({ "exec_claude": "2.1.287 (Claude Code)", "exec_uid": "1000", "exec_curl": "401", "exec_proxy_vars": "6", "exec_ok": true, "exec_ms": 42, "exec_problems": [] });
        assert_eq!(serde_json::Value::Object(rec), want);
    }

    /// A step that printed something else, or exited otherwise (its stderr's
    /// first line named), is a problem: `exec_ok` false, one line each.
    #[test]
    fn a_smoke_step_that_fails_is_a_problem_naming_what_it_printed() {
        let plan = smoke_plan(&row("vpc"), None);
        let cap = |out: &str, err: &str, status: i32| Captured { stdout: out.into(), stderr: err.into(), status };
        let steps = vec![
            judged(plan[0].0, &command_line(&plan[0].1), &plan[0].2, &cap("2.1.287 (Claude Code)\n", "", 0), 5),
            judged(plan[1].0, &command_line(&plan[1].1), &plan[1].2, &cap("501\n", "", 0), 5),
            judged(plan[2].0, &command_line(&plan[2].1), &plan[2].2, &cap("000", "curl: (7) Failed to connect to the proxy\nmore\n", 7), 5),
            judged(plan[3].0, &command_line(&plan[3].1), &plan[3].2, &cap("6\n", "", 1), 5),
        ];
        let ran = SmokeExec { steps, ms: 9 };
        assert!(!ran.ok());
        assert_eq!(
            ran.problems(),
            [
                "exec id -u → \"501\" in 5 ms (expected \"1000\", exit 0): MISMATCH",
                "exec curl -sS --connect-timeout 10 --max-time 30 -o /dev/null -w %{http_code} https://api.anthropic.com/v1/models → \"000\" in 5 ms (expected \"401\", exit 7): curl: (7) Failed to connect to the proxy: MISMATCH",
                "exec sh -c 'env | grep -ci _proxy' → \"6\" in 5 ms (expected \"6\", exit 1): MISMATCH",
            ]
        );
        let mut rec = serde_json::Map::new();
        ran.record(&mut rec);
        assert_eq!((rec["exec_ok"].as_bool(), rec["exec_uid"].as_str(), rec["exec_problems"].as_array().map(Vec::len)), (Some(false), Some("501"), Some(3)));
    }

    /// `vm health --detail`'s summary: the guard, the hooks, the spawns (one
    /// whose group outlived its leader reads `group`, with a note, never
    /// `no`: F15), the listeners (a row each), the clock, and (S7) the
    /// credential: the cache's copy by name and seal, never the value, the
    /// running commands handed a secret, which hold it whatever the cache
    /// says (so "no copy cached" is never read as "no copy on the VM"), and
    /// when this Mac's row says the VM received the token (M51).
    #[test]
    fn detail_lines_name_the_guard_spawns_and_clock() {
        use crate::wire::frame::{CredentialView, ExitInfo, Health, HealthStatus, ListenerInfo, SpawnDetail, SpawnStatus};
        let spawn = SpawnStatus { spawn_id: SpawnId::new_v7(), argv0: "cat".into(), pid: 42, pgid: 42, alive: false, attached: true, out_seq: 7, out_from: 3, err_seq: 2, in_seq: 5, stdin_closed: true, exit: Some(ExitInfo { code: None, signal: Some(15) }) };
        let d = HealthDetail {
            health: Health { status: HealthStatus::Ok, shim_version: "0.1.0".into(), claude_version: Some("2.1.287".into()), microvm_id: Some(ID.into()), owner: None, created: None, boot_nonce: None, run_hook_seen: true, uptime_s: 12, wire: Some(1), caps: vec![] },
            image_version: Some("7.0".into()),
            hook_source: "peer".into(),
            agent_guard: "on".into(),
            refused_peers: BTreeMap::from([("9000".to_string(), 2)]),
            hook_peers: BTreeMap::from([("run".to_string(), HookPeerSeen { peer: "127.0.0.1:41000".into(), family: Some(4), uid: Some(0), inode: Some(99), decision: "admitted".into(), at: "2026-10-03T08:00:00Z".into() })]),
            hook_refusals: BTreeMap::new(),
            sockets_open: 1,
            sockets_authenticated: 1,
            spawns: vec![SpawnDetail { status: spawn, started_at: "2026-10-03T08:00:01Z".into(), detach_left_s: None, frozen: false, group_alive: false }],
            has_credentials: false,
            clock: Some(serde_json::json!({"hook": "resume", "drift_s": 0, "mode": "measure"})),
            listeners: vec![
                ListenerInfo { addr: "0.0.0.0".into(), port: 8080, uid: 0, inode: 1, own: true },
                ListenerInfo { addr: "127.0.0.1".into(), port: 8022, uid: 0, inode: 2, own: false },
                ListenerInfo { addr: "::1".into(), port: 631, uid: 1000, inode: 3, own: false },
            ],
            listeners_omitted: 0,
            credential: Default::default(),
        };
        let lines = detail_lines(&d, None);
        let text = lines.join("\n");
        for want in ["ok shim 0.1.0 claude 2.1.287 image 7.0", "hook_source peer, agent_guard on; refused peers: 9000=2", "run admitted uid 0 ino 99", "refusals   none", "cat", "3..7", "signal 15", "listeners  3 (1 the shim's own)", "credentials no", "last report on resume (drift 0 s, mode measure)"] {
            assert!(text.contains(want), "{want}: {text}");
        }
        // F15: `alive` is the leader alone; a group that outlived it reads `group`, with a note, never `no`.
        let id = d.spawns[0].status.spawn_id.to_string();
        let row = |lines: &[String]| lines.iter().find(|l| l.contains(&id)).cloned().unwrap_or_default();
        assert!(row(&lines).contains("      42 no    yes ") && !text.contains("ALIVE group"), "{text}");
        let group = detail_lines(&HealthDetail { spawns: vec![SpawnDetail { group_alive: true, ..d.spawns[0].clone() }], ..d.clone() }, None);
        assert!(row(&group).contains("      42 group yes "), "{group:?}");
        assert!(group.contains(&"  (ALIVE group: the leader exited, but a process of its group still runs, with whatever the command was handed)".to_string()), "{group:?}");
        // Each listener on a row of its own under the count (address, port, uid, inode, the shim's own).
        let at = lines.iter().position(|l| l.starts_with("  listeners  ")).unwrap();
        assert_eq!(lines[at + 1..at + 4], ["             0.0.0.0:8080 uid 0 inode 1 own", "             127.0.0.1:8022 uid 0 inode 2", "             [::1]:631 uid 1000 inode 3"], "{text}");
        assert!(lines[at + 4].starts_with("  credentials "), "{text}");
        let text = detail_lines(&HealthDetail { listeners_omitted: 91, ..d.clone() }, None).join("\n");
        assert!(text.contains("listeners  3 (1 the shim's own; 91 more not listed)"), "{text}");
        let held = detail_lines(&HealthDetail { credential: CredentialView { credential_holders: 1, ..CredentialView::default() }, ..d.clone() }, None).join("\n");
        assert!(held.contains("  credentials no copy cached; 1 running command was handed a secret: it, and any snapshot taken while it runs, holds it until the VM is terminated"), "{held}");
        let view = CredentialView { credential_name: Some("CLAUDE_CODE_OAUTH_TOKEN".into()), credential_tag: Some("seal0123456789ab".into()), credential_at: Some("2026-10-07T10:00:00Z".into()), credential_holders: 2 };
        let cached = detail_lines(&HealthDetail { has_credentials: true, credential: view, ..d.clone() }, None).join("\n");
        assert!(cached.contains("  credentials yes: CLAUDE_CODE_OAUTH_TOKEN cached (seal seal0123456789ab, at 2026-10-07T10:00:00Z); 2 running commands were handed a secret: they,"), "{cached}");
        let received = detail_lines(&d, Some(("2026-10-07T09:59:58Z", Some("seal0123456789ab")))).join("\n");
        assert!(received.contains("  credentials no copy cached; this Mac's row: a token was last sent to it (seal seal0123456789ab) at 2026-10-07T09:59:58Z"), "{received}");
        let none = detail_lines(&HealthDetail { listeners: Vec::new(), listeners_omitted: 0, ..d }, None);
        let at = none.iter().position(|l| l.starts_with("  listeners  ")).unwrap();
        assert_eq!((none[at].as_str(), none[at + 1].starts_with("  credentials ")), ("  listeners  0 (0 the shim's own)", true));
    }
}
