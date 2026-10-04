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
//!   a refused name, never a value.
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
//!   holds the exit at most 3 s more, and another signal ends it at once.
//! - **Exit status** (S6 D8): the remote code verbatim, 128 + N for a signal,
//!   through a silent `CliError::Exit` — also after a SIGINT the spawn got
//!   (the remote decides what INT means). The operator's own endings win over
//!   the remote's: 143 after SIGTERM or SIGHUP (whatever the remote did within
//!   the 2 s; plan S6), 130 after a SIGINT before the spawn ran (or a second
//!   one while nothing reached the VM), 0 after EPIPE, and 130/143 for a
//!   signal that cut the last flush short. ai-env's own failures keep 7/8/9
//!   with their `ai-env:` line; the shim's limit of live spawns is a refusal
//!   (9) naming `vm health --detail`. One `vm_exec` / `vm_attach` audit row:
//!   the id, argv[0]'s basename, the spawn, the status and the time — never
//!   an argument or the environment.
//! - **`vm smoke --exec`** ([`smoke_exec`]): `claude --version`, `id -u` and,
//!   on vpc, `curl` to the API (401 through the proxy) and the proxy variable
//!   count, each a session of its own with an in-memory consumer, bounded by
//!   120 s.
use super::{run_spawn, spawn_channels, AgentEnv, AgentTarget, Consumed, ConsumerIo, RunPolicy, SpawnEvent, SpawnInput, SpawnSpec, Start};
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo};
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
}

impl std::fmt::Debug for ExecPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExecPlan({}, argv0={}, argc={}, env={}, cwd={}, detach_grace_s={:?})",
            self.id,
            argv0(&self.argv),
            self.argv.len(),
            self.env.len(),
            if self.cwd.is_some() { "set" } else { "default" },
            self.detach_grace_s
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

/// Validate `vm exec`'s flags and the VM's row (see the module doc).
pub fn check_exec(ctx: &Ctx, id: &str, cwd: Option<String>, env: &[String], detach_grace_s: Option<u32>, argv: Vec<String>) -> Result<ExecPlan> {
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
    let plan = ExecPlan { id: id.to_string(), row, cwd, env, detach_grace_s, argv };
    check_frame(&plan)?;
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
fn spawn_env(ctx: &Ctx, row: &VmRow, user: &[(String, String)]) -> BTreeMap<String, String> {
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
fn agent_env<'a, A: MicrovmApi, E: EndpointClient>(ctx: &'a Ctx, api: &'a A, ep: &'a E, row: &VmRow, vm: Option<&VmInfo>) -> Result<AgentEnv<'a, A, E>> {
    let mut row = row.clone();
    if let Some(endpoint) = vm.map(|v| v.endpoint.clone()).filter(|e| !e.is_empty()) {
        row.endpoint = Some(endpoint);
    }
    let target = AgentTarget::from_row(&row)?;
    let dial = AgentDial { local: ctx.knobs.agent_addr().map_err(CliError::Usage)? };
    Ok(AgentEnv { api, ep, paths: &ctx.paths, target, policy: RunPolicy::from_cfg(&ctx.cfg.transport, &row, ctx.knobs.backoff_ms), dial })
}

/// `vm exec`.
pub async fn run_exec<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, plan: ExecPlan) -> Result<()> {
    let started = Instant::now();
    let name = argv0(&plan.argv).to_string();
    let run = async {
        let vm = live_vm(api, &plan.id).await?;
        let env = agent_env(ctx, api, ep, &plan.row, Some(&vm))?;
        let spec = SpawnSpec { argv: plan.argv.clone(), cwd: plan.cwd.clone(), env: spawn_env(ctx, &plan.row, &plan.env), detach_grace_s: plan.detach_grace_s };
        pump(&env, Start::New(spec), true).await
    };
    let (result, spawn) = finish(run.await);
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
        pump(&env, Start::Attach { spawn_id: plan.spawn_id.clone(), from_seq: plan.from_seq, err_from_seq: None }, stdin).await
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
}

/// `Pumped` → the command's result (0: `Ok`; a remote status: the silent `Exit`).
fn finish(r: Result<Pumped>) -> (Result<()>, Option<SpawnId>) {
    match r {
        Ok(Pumped { result: Ok(0), spawn }) => (Ok(()), spawn),
        Ok(Pumped { result: Ok(status), spawn }) => (Err(CliError::Exit(status)), spawn),
        Ok(Pumped { result: Err(e), spawn }) => (Err(e), spawn),
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
}

impl Ending {
    fn result(self) -> std::result::Result<i32, CliError> {
        match self {
            Ending::Term => Ok(TERM_STATUS),
            Ending::Interrupted => Ok(INT_STATUS),
            Ending::Stdout(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(0),
            Ending::Stdout(e) => Err(CliError::Msg(format!("vm exec: writing stdout failed ({e}); the remote command was stopped"))),
        }
    }
}

/// A handler for `sig`, or none when it was ignored when ai-env started
/// (`nohup`, a non-interactive shell's background job): it then stays
/// ignored, as ssh leaves it. Read before tokio's handler would replace it.
fn handle(sig: libc::c_int, kind: tokio::signal::unix::SignalKind) -> Result<Option<tokio::signal::unix::Signal>> {
    if ignored(sig) {
        tracing::info!("vm exec: signal {sig} was ignored when ai-env started: it stays ignored");
        return Ok(None);
    }
    tokio::signal::unix::signal(kind).map(Some).map_err(|e| CliError::Msg(format!("cannot handle signals: {e}")))
}

/// Whether `sig`'s disposition is `SIG_IGN`.
fn ignored(sig: libc::c_int) -> bool {
    // SAFETY: a null new action makes sigaction(2) only read the current one
    // into `old`, a zeroed (valid) `struct sigaction`.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &raw mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// The next delivery of `s`; never while the signal stays ignored.
async fn delivered(s: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match s {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

/// One attachment with the process's stdio and signals (see the module doc);
/// `stdin`: this process's stdin feeds the remote's.
async fn pump<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, start: Start, stdin: bool) -> Result<Pumped> {
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
    let mut session = Box::pin(run_spawn(env, start, io));
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
    let stopping = matches!(ending, Some(Ending::Term | Ending::Interrupted));
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
    let result = match (outcome, ending) {
        // ai-env's own failure while TERM's 2 s ran (or its detach waited for the link), before any detach.
        (Some(Err(e)), Some(Ending::Term)) if !detached => Err(session_error(e, &err, &view.vm)),
        // The operator ended it: their status, whatever the remote did (S6:
        // TERM, at most 2 s, then 143; a broken pipe is 0).
        (_, Some(e)) => e.result(),
        (Some(Ok(o)), None) => Ok(o.exit.status()),
        (Some(Err(e)), None) => Err(session_error(e, &err, &view.vm)),
        // The loop gives up only with an ending.
        (None, None) => Ok(TERM_STATUS),
    };
    let pumped = Pumped { result, spawn };
    // Everything delivered is written before the process exits. Once the
    // operator asked to stop, a stdout nobody reads holds the exit only
    // `DETACH_WAIT`; another signal ends the wait at once.
    let flushed = tokio::task::spawn_blocking(move || {
        out.close();
        err.close();
    });
    let bound = stopping.then(|| tokio::time::Instant::now() + DETACH_WAIT);
    tokio::select! {
        _ = flushed => {}
        () = at(bound) => {}
        Some(()) = delivered(&mut term) => return Ok(Pumped { result: Ok(TERM_STATUS), ..pumped }),
        Some(()) = delivered(&mut hup) => return Ok(Pumped { result: Ok(TERM_STATUS), ..pumped }),
        Some(()) = delivered(&mut int) => return Ok(Pumped { result: Ok(INT_STATUS), ..pumped }),
    }
    Ok(pumped)
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
}

impl View {
    fn new(vm: &str) -> View {
        View { vm: vm.to_string(), spawn: None, linked: false, given_up: false, show_spawn: std::io::stderr().is_terminal(), dropped: Dropped::default() }
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
            SpawnEvent::Stdout { seq, bytes } => out.chunk(seq, bytes),
            SpawnEvent::Stderr { seq, bytes, dropped } => {
                if let Some(n) = self.dropped.chunk(dropped, Instant::now()) {
                    note_dropped(err, n);
                }
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
    if json {
        let v = serde_json::json!({ "backend": ctx.backend_name(), "id": id, "detail": detail });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
        return Ok(());
    }
    for line in detail_lines(&detail) {
        outln!("{line}");
    }
    Ok(())
}

/// The human summary of `/health/detail`.
fn detail_lines(d: &HealthDetail) -> Vec<String> {
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
            out.push(format!("  {:<36} {argv0:<12} {:>7} {:<5} {:<8} {:>13} {:>7} {:>7} {exit}", st.spawn_id, st.pid, yes(st.alive), yes(st.attached), format!("{}..{}", st.out_from, st.out_seq), st.err_seq, st.in_seq));
        }
    }
    let more = if d.listeners_omitted > 0 { format!("; {} more not listed", d.listeners_omitted) } else { String::new() };
    out.push(format!("  listeners  {} ({} the shim's own{more})", d.listeners.len(), d.listeners.iter().filter(|l| l.own).count()));
    // One row each, as in-vm-firewall's note names them (a `listeners` gap is investigated here).
    for l in &d.listeners {
        let at = if l.addr.contains(':') { format!("[{}]:{}", l.addr, l.port) } else { format!("{}:{}", l.addr, l.port) };
        out.push(format!("             {at} uid {} inode {}{}", l.uid, l.inode, if l.own { " own" } else { "" }));
    }
    out.push(format!("  credentials {}", yes(d.has_credentials)));
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
async fn capture<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, spec: SpawnSpec) -> std::result::Result<Captured, BridgeError> {
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
    let run = tokio::time::timeout(SMOKE_STEP_LIMIT, run_spawn(env, Start::New(spec), io));
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
        plan.push(("exec_curl", vec!["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com/v1/models"], Want::Exactly("401".into())));
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
        match capture(env, spec).await {
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
        check_exec(c, ID, None, &env.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(), None, argv.iter().map(|s| (*s).to_string()).collect())
    }

    #[test]
    fn flags_are_usage_errors_before_the_row_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let code = |r: Result<ExecPlan>| r.unwrap_err().exit_code();
        assert_eq!(code(check_exec(&c, "bad/id", None, &[], None, vec!["true".into()])), 2);
        assert_eq!(code(exec(&c, &[], &[])), 2, "empty argv");
        assert_eq!(code(exec(&c, &[], &[""])), 2, "empty argv[0]");
        let long = "x".repeat(ARGV_MAX_BYTES);
        assert_eq!(code(exec(&c, &[], &["echo", &long])), 2);
        for bad in ["relative/dir", "/a/../b", "/a/./b", "."] {
            assert_eq!(code(check_exec(&c, ID, Some(bad.into()), &[], None, vec!["true".into()])), 2, "{bad}");
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
                ("exec_curl", vec!["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com/v1/models"], Want::Exactly("401".into())),
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
        assert_eq!(steps[2].line, "exec curl -sS -o /dev/null -w %{http_code} https://api.anthropic.com/v1/models → \"401\" in 7 ms (expected \"401\", exit 0): ok");
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
                "exec curl -sS -o /dev/null -w %{http_code} https://api.anthropic.com/v1/models → \"000\" in 5 ms (expected \"401\", exit 7): curl: (7) Failed to connect to the proxy: MISMATCH",
                "exec sh -c 'env | grep -ci _proxy' → \"6\" in 5 ms (expected \"6\", exit 1): MISMATCH",
            ]
        );
        let mut rec = serde_json::Map::new();
        ran.record(&mut rec);
        assert_eq!((rec["exec_ok"].as_bool(), rec["exec_uid"].as_str(), rec["exec_problems"].as_array().map(Vec::len)), (Some(false), Some("501"), Some(3)));
    }

    #[test]
    fn detail_lines_name_the_guard_spawns_and_clock() {
        use crate::wire::frame::{ExitInfo, Health, HealthStatus, ListenerInfo, SpawnDetail, SpawnStatus};
        let spawn = SpawnStatus { spawn_id: SpawnId::new_v7(), argv0: "cat".into(), pid: 42, pgid: 42, alive: false, attached: true, out_seq: 7, out_from: 3, err_seq: 2, in_seq: 5, stdin_closed: true, exit: Some(ExitInfo { code: None, signal: Some(15) }) };
        let d = HealthDetail {
            health: Health { status: HealthStatus::Ok, shim_version: "0.1.0".into(), claude_version: Some("2.1.287".into()), microvm_id: Some(ID.into()), owner: None, created: None, boot_nonce: None, run_hook_seen: true, uptime_s: 12, wire: Some(1) },
            image_version: Some("7.0".into()),
            hook_source: "peer".into(),
            agent_guard: "on".into(),
            refused_peers: BTreeMap::from([("9000".to_string(), 2)]),
            hook_peers: BTreeMap::from([("run".to_string(), HookPeerSeen { peer: "127.0.0.1:41000".into(), family: Some(4), uid: Some(0), inode: Some(99), decision: "admitted".into(), at: "2026-10-03T08:00:00Z".into() })]),
            hook_refusals: BTreeMap::new(),
            sockets_open: 1,
            sockets_authenticated: 1,
            spawns: vec![SpawnDetail { status: spawn, started_at: "2026-10-03T08:00:01Z".into(), detach_left_s: None, frozen: false }],
            has_credentials: false,
            clock: Some(serde_json::json!({"hook": "resume", "drift_s": 0, "mode": "measure"})),
            listeners: vec![
                ListenerInfo { addr: "0.0.0.0".into(), port: 8080, uid: 0, inode: 1, own: true },
                ListenerInfo { addr: "127.0.0.1".into(), port: 8022, uid: 0, inode: 2, own: false },
                ListenerInfo { addr: "::1".into(), port: 631, uid: 1000, inode: 3, own: false },
            ],
            listeners_omitted: 0,
        };
        let lines = detail_lines(&d);
        let text = lines.join("\n");
        for want in ["ok shim 0.1.0 claude 2.1.287 image 7.0", "hook_source peer, agent_guard on; refused peers: 9000=2", "run admitted uid 0 ino 99", "refusals   none", "cat", "3..7", "signal 15", "listeners  3 (1 the shim's own)", "credentials no", "last report on resume (drift 0 s, mode measure)"] {
            assert!(text.contains(want), "{want}: {text}");
        }
        // Each listener on a row of its own under the count (address, port, uid, inode, the shim's own).
        let at = lines.iter().position(|l| l.starts_with("  listeners  ")).unwrap();
        assert_eq!(lines[at + 1..at + 4], ["             0.0.0.0:8080 uid 0 inode 1 own", "             127.0.0.1:8022 uid 0 inode 2", "             [::1]:631 uid 1000 inode 3"], "{text}");
        assert!(lines[at + 4].starts_with("  credentials "), "{text}");
        let text = detail_lines(&HealthDetail { listeners_omitted: 91, ..d.clone() }).join("\n");
        assert!(text.contains("listeners  3 (1 the shim's own; 91 more not listed)"), "{text}");
        let none = detail_lines(&HealthDetail { listeners: Vec::new(), listeners_omitted: 0, ..d });
        let at = none.iter().position(|l| l.starts_with("  listeners  ")).unwrap();
        assert_eq!((none[at].as_str(), none[at + 1].starts_with("  credentials ")), ("  listeners  0 (0 the shim's own)", true));
    }
}
