//! `ai-env box …` (S8): the workspace a VM works in, from the Mac's side.
//! `box seed` carries the workspace into its VM at the identical path — a
//! shallow pack of HEAD's commit and tree plus a scanned snapshot of the
//! uncommitted changes (D2, D7), never the history — and `box fetch` brings
//! the VM's commits and a snapshot of its uncommitted work back into
//! `refs/remotes/box/*`, never into the user's branches or working tree.
//! `box seed --dry-run` works offline (no AWS call, no Touch ID). The module
//! is `boxcmd` because `box` is a reserved word. Built in S8 wave 1 (W4).
//!
//! Everything that can be refused locally is refused before the Touch ID:
//! the workspace (D6, the roots, an unsupported repository), the snapshot's
//! caps and every scan of what a seed carries. The VM is the workspace's own
//! (`vm run --workspace` or `vm warm` started it; `box` never starts one), or
//! for `box fetch SESSION` the session's.
use crate::bridge::agent::AgentTarget;
use crate::bridge::api::{EndpointClient, MicrovmApi, VmState};
use crate::bridge::codeout::{box_ref_of, credential_shaped, fetch, hidden_note, CodeoutCtx, FetchOpts, BOX_REFS};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::dataplane::{exchange, DpReply, Exchange, HttpsEndpoint, MintingTokens, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::cmd::{backend, runtime, Backend, Ctx};
use crate::bridge::vm::health::{read_health, Backoff};
use crate::bridge::vm::registry::{list_rows, read_row, RowStatus, VmRow};
use crate::bridge::voice;
use crate::bridge::workspace::blobscan::ScanSet;
use crate::bridge::workspace::snapshot::human_bytes;
use crate::bridge::workspace::{ensure_workspace, prepare_with, resolve, workspace_cfg, EnsureCtx, EnsureOutcome, PreparedSeed, SeedLimits, SeedProgress, SeedWant, WorkspaceRef};
use crate::cli::BoxCmd;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::workspace::{CodeoutRequest, CODE_PORT, SEED_BODY_MAX};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MIB: u64 = 1024 * 1024;

/// `ai-env box …`.
pub fn main(store: &Keystore, cmd: BoxCmd) -> Result<()> {
    match cmd {
        BoxCmd::Seed { workspace, branch, no_wip, replace, dry_run, max_mib, json } => seed(store, &Seed { workspace, branch, no_wip, replace, dry_run, max_mib, json }),
        BoxCmd::Fetch { target, wip, dry_run, max_mib, json } => fetch_cmd(store, target.as_deref(), wip, dry_run, max_mib, json),
    }
}

/// `box seed`'s flags.
struct Seed {
    workspace: Option<PathBuf>,
    branch: Option<String>,
    no_wip: bool,
    replace: bool,
    dry_run: bool,
    max_mib: Option<u32>,
    json: bool,
}

/// The workspace directory a command acts on: the argument, else the current directory.
fn workspace_dir(arg: Option<&Path>) -> Result<PathBuf> {
    match arg {
        Some(p) => Ok(p.to_path_buf()),
        None => std::env::current_dir().map_err(|e| CliError::Msg(format!("cannot read the current directory: {e}"))),
    }
}

/// bridge.toml, which `box` needs for `[workspaces].roots` and `[seed]`.
fn load_config(paths: &Paths) -> Result<BridgeConfig> {
    let cfg = BridgeConfig::load(paths)?.ok_or_else(|| CliError::Msg(format!("{} not found: run `make infra-status WRITE=1` and set [workspaces].roots", paths.config.display())))?;
    cfg.seed.validate()?;
    Ok(cfg)
}

/// `box seed [WORKSPACE] [--branch B] [--no-wip] [--replace] [--dry-run] [--max-mib N] [--json]`.
fn seed(store: &Keystore, a: &Seed) -> Result<()> {
    let dir = workspace_dir(a.workspace.as_deref())?;
    if a.dry_run {
        let paths = Paths::resolve()?;
        let cfg = load_config(&paths)?;
        let (ws, lim, prepared) = prepare_seed(&paths, &cfg, &dir, a)?;
        return dry_run(&ws, &lim, &prepared, a.json);
    }
    let ctx = Ctx::load()?;
    ctx.cfg.seed.validate()?;
    let (ws, lim, prepared) = prepare_seed(&ctx.paths, &ctx.cfg, &dir, a)?;
    let want = if a.replace { SeedWant::Replace } else { SeedWant::Auto };
    let rt = runtime()?;
    rt.block_on(async {
        match backend(store, &ctx).await? {
            Backend::Sdk(api, ep) => seed_on(&ctx, api, &*ep, &ws, lim, prepared, want, a.json).await,
            Backend::Fake(f) => seed_on(&ctx, Arc::new(f.clone()), &f, &ws, lim, prepared, want, a.json).await,
        }
    })
}

/// Resolve, snapshot, list and scan (local: before any Touch ID).
fn prepare_seed(paths: &Paths, cfg: &BridgeConfig, dir: &Path, a: &Seed) -> Result<(WorkspaceRef, SeedLimits, PreparedSeed)> {
    let ws = resolve(cfg, dir, a.branch.as_deref())?;
    let lim = SeedLimits::cli(cfg, a.max_mib);
    let with_wip = !a.no_wip && workspace_cfg(cfg, &ws).is_none_or(|w| w.seed_wip);
    let prepared = prepare_with(paths, cfg, &ws, &lim, with_wip)?;
    for note in &prepared.summary().notes {
        voice::note(note);
    }
    Ok((ws, lim, prepared))
}

/// `box seed --dry-run`: the plan of a first seed, nothing sent.
fn dry_run(ws: &WorkspaceRef, lim: &SeedLimits, prepared: &PreparedSeed, json: bool) -> Result<()> {
    let s = prepared.summary();
    let body = prepared.first_body(lim.max_bytes)?;
    let pack = body.as_ref().map(|b| b.len);
    if json {
        let v = serde_json::json!({
            "dry_run": true,
            "workspace": ws.cwd.display().to_string(),
            "root": ws.root.display().to_string(),
            "vm_cwd": ws.vm_cwd,
            "vm_root": ws.vm_root,
            "slug": ws.slug,
            "seed": s,
            "pack_bytes": pack,
            "cap_bytes": lim.max_bytes,
            "over_cap": pack.is_none(),
        });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        outln!("box seed --dry-run: {} (in the VM: {})", ws.root.display(), ws.vm_root);
        match &s.branch {
            Some(b) => outln!("  head {} on {b}", short(&s.head)),
            None => outln!("  head {} (detached)", short(&s.head)),
        }
        match &s.wip {
            Some(w) => outln!("  uncommitted: {} path(s) changed, {} untracked file(s), {} new (WIP {}{})", w.changed, w.untracked, human_bytes(w.new_bytes), short(&w.commit), w.index_commit.as_deref().map(|i| format!(", index {}", short(i))).unwrap_or_default()),
            None => outln!("  uncommitted: none carried"),
        }
        let trust = if s.trust_repo_settings { " (trust_repo_settings: the repo mode is off)" } else { "" };
        outln!("  scan: {} object(s), {} from the clean cache, {} settings file(s): clean{trust}", s.objects, s.cached, s.settings_files);
        match pack {
            Some(n) => outln!("  pack: {} (cap {}), HEAD's commit and tree and the WIP, no history", human_bytes(n), human_bytes(lim.max_bytes)),
            None => outln!("  pack: over the cap of {}", human_bytes(lim.max_bytes)),
        }
        outln!("nothing was sent: no AWS call, no Touch ID");
    }
    if pack.is_none() {
        return Err(BridgeError::WorkspaceRefused { code: crate::wire::workspace::refusal::TOO_LARGE, message: format!("the seed is over {} (box seed --max-mib, [seed].max_mib)", human_bytes(lim.max_bytes)) }.into());
    }
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// The workspace's VM: a row of `ws` (its cwd, else its root), not
/// terminated, not a `--shell` row, that the control plane still runs or
/// holds suspended; the newest first.
async fn workspace_vm<A: MicrovmApi>(paths: &Paths, api: &A, ws: &WorkspaceRef) -> std::result::Result<VmRow, BridgeError> {
    let keys = [ws.cwd.to_string_lossy().into_owned(), ws.root.to_string_lossy().into_owned()];
    let rows = list_rows(paths)?;
    for key in &keys {
        for row in rows.iter().filter(|r| !r.is_pending_row() && r.workspace.as_deref() == Some(key.as_str()) && r.status != RowStatus::Terminated && !r.shell) {
            match api.get(&row.id).await {
                Ok(vm) if matches!(vm.state, VmState::Running | VmState::Suspended | VmState::Suspending | VmState::Pending) => return Ok(row.clone()),
                Ok(_) | Err(BridgeError::VmNotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Err(BridgeError::VmNotFound(format!("no running VM for {} (`ai-env vm warm {}` starts one and seeds it)", ws.cwd.display(), ws.cwd.display())))
}

/// The VM's caps: its row's, else its `/health`'s (which the row then records).
async fn caps_of<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow) -> std::result::Result<Vec<String>, BridgeError> {
    match &row.caps {
        Some(caps) => Ok(caps.clone()),
        None => Ok(read_health(api, ep, &ctx.paths, &row.id, Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?.0.caps),
    }
}

/// `box seed` on the workspace's VM.
#[allow(clippy::too_many_arguments)]
async fn seed_on<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: Arc<A>, ep: &E, ws: &WorkspaceRef, lim: SeedLimits, prepared: PreparedSeed, want: SeedWant, json: bool) -> Result<()> {
    let row = workspace_vm(&ctx.paths, &*api, ws).await?;
    let caps = caps_of(ctx, &*api, ep, &row).await?;
    let target = AgentTarget::from_row(&row)?;
    let dp = HttpsEndpoint::new(&ctx.knobs)?;
    let tokens = MintingTokens::new(api.clone(), &ctx.paths, &row.id, true);
    let progress = |p: SeedProgress| match p {
        SeedProgress::Packed { bytes } => voice::note(&format!("seed of {}: {} to send", row.id, human_bytes(bytes))),
        SeedProgress::Applied => voice::note(&format!("seed of {}: checked out", row.id)),
        _ => {}
    };
    let ectx = EnsureCtx { api: &*api, dp: &dp, tokens: &tokens, paths: &ctx.paths, cfg: &ctx.cfg, target: &target, caps: &caps, ws, lim, deadline: None, progress: &progress };
    let outcome = ensure_workspace(&ectx, Some(prepared), want).await?;
    if json {
        let v = serde_json::json!({ "backend": ctx.backend_name(), "vm": row.id, "workspace": ws.cwd.display().to_string(), "outcome": outcome.word(), "detail": outcome_json(&outcome) });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        match &outcome {
            EnsureOutcome::Seeded { head, wip, bytes, ms } => outln!("seeded {}: {}{} ({}, {:.1} s)", row.id, short(head), wip.as_deref().map(|w| format!(" with the uncommitted changes (WIP {})", short(w))).unwrap_or_default(), human_bytes(*bytes), *ms as f64 / 1000.0),
            EnsureOutcome::Updated { from, head, bytes, .. } => outln!("updated {}: {} -> {} ({})", row.id, short(from), short(head), human_bytes(*bytes)),
            EnsureOutcome::UpToDate { head } => outln!("up to date: {} holds {}", row.id, short(head)),
            EnsureOutcome::Kept { note, .. } => outln!("kept: {}: {note}", row.id),
        }
    }
    Ok(())
}

fn outcome_json(o: &EnsureOutcome) -> serde_json::Value {
    match o {
        EnsureOutcome::Seeded { head, wip, bytes, ms } => serde_json::json!({ "head": head, "wip": wip, "bytes": bytes, "ms": ms }),
        EnsureOutcome::Updated { from, head, wip, bytes } => serde_json::json!({ "from": from, "head": head, "wip": wip, "bytes": bytes }),
        EnsureOutcome::UpToDate { head } => serde_json::json!({ "head": head }),
        EnsureOutcome::Kept { reason, vm_head, note } => serde_json::json!({ "reason": reason.word(), "vm_head": vm_head, "note": note }),
    }
}

/// `box fetch [SESSION or WORKSPACE] [--wip] [--dry-run] [--max-mib N] [--json]`.
fn fetch_cmd(store: &Keystore, target: Option<&str>, wip: bool, dry_run: bool, max_mib: Option<u32>, json: bool) -> Result<()> {
    let ctx = Ctx::load()?;
    ctx.cfg.seed.validate()?;
    let (dir, vm) = match target.filter(|t| crate::bridge::registry::is_uuid(t)) {
        Some(id) => {
            let row = crate::bridge::registry::read(&ctx.paths, id)?.ok_or_else(|| CliError::Msg(format!("no session {id} in {}", ctx.paths.sessions().display())))?;
            let cwd = row.cwd.clone().ok_or_else(|| CliError::Msg(format!("session {id} names no workspace")))?;
            (PathBuf::from(cwd), row.microvm_id.clone())
        }
        None => (workspace_dir(target.map(Path::new))?, None),
    };
    let ws = resolve(&ctx.cfg, &dir, None)?;
    let max_bytes = u64::from(max_mib.unwrap_or(ctx.cfg.seed.max_fetch_mib)) * MIB;
    let rt = runtime()?;
    rt.block_on(async {
        match backend(store, &ctx).await? {
            Backend::Sdk(api, ep) => fetch_on(&ctx, api, &*ep, &ws, vm.as_deref(), FetchOpts { wip, max_bytes }, dry_run, json).await,
            Backend::Fake(f) => fetch_on(&ctx, Arc::new(f.clone()), &f, &ws, vm.as_deref(), FetchOpts { wip, max_bytes }, dry_run, json).await,
        }
    })
}

/// `box fetch` from the session's or the workspace's VM.
#[allow(clippy::too_many_arguments)]
async fn fetch_on<A: MicrovmApi + 'static, E: EndpointClient>(ctx: &Ctx, api: Arc<A>, ep: &E, ws: &WorkspaceRef, vm: Option<&str>, opts: FetchOpts, dry_run: bool, json: bool) -> Result<()> {
    let row = match vm {
        Some(id) => read_row(&ctx.paths, id)?.ok_or_else(|| BridgeError::VmNotFound(format!("{id} (the session's VM) has no row")))?,
        None => workspace_vm(&ctx.paths, &*api, ws).await?,
    };
    let caps = caps_of(ctx, &*api, ep, &row).await?;
    crate::bridge::workspace::require_capability(&caps, &row.id)?;
    let target = AgentTarget::from_row(&row)?;
    let dp = HttpsEndpoint::new(&ctx.knobs)?;
    let tokens = MintingTokens::new(api.clone(), &ctx.paths, &row.id, false);
    if dry_run {
        return fetch_dry_run(ctx, &*api, &dp, &tokens, &target, ws, json).await;
    }
    let cctx = CodeoutCtx { api: api.clone(), dp: Arc::new(dp), tokens: Arc::new(tokens), paths: ctx.paths.clone(), cfg: Arc::new(ctx.cfg.clone()), target, ws: ws.clone(), capture_settings: false };
    let report = fetch(&cctx, opts).await?;
    if json {
        let v = serde_json::json!({ "backend": ctx.backend_name(), "vm": row.id, "report": report });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        if report.promoted.is_empty() && report.quarantined.is_empty() {
            outln!("nothing new from {}", row.id);
        }
        for (name, id) in &report.promoted {
            outln!("{name} -> {}", short(id));
        }
        for (name, id) in &report.quarantined {
            outln!("{name} -> {} (quarantined)", short(id));
        }
        if let Some(note) = &report.note {
            voice::note(note);
        }
    }
    if !report.quarantined.is_empty() {
        return Err(CliError::Policy(format!(
            "{} ref(s) from {} hold a finding and went to refs/remotes/box-quarantine/*: review them before any merge ({})",
            report.quarantined.len(),
            row.id,
            report.note.as_deref().unwrap_or("see the workspace row")
        )));
    }
    Ok(())
}

/// `box fetch --dry-run`: the VM's refs (a code-out's manifest, read without
/// its pack and without a snapshot) against `refs/remotes/box/*`. A name
/// that looks like a credential (`codeout::credential_shaped`, the scans'
/// rules), a ref's or the checked-out branch's, is never printed: such refs
/// are only counted, as a fetch keeps them out.
async fn fetch_dry_run<A: MicrovmApi>(ctx: &Ctx, api: &A, dp: &HttpsEndpoint, tokens: &MintingTokens<Arc<A>>, target: &AgentTarget, ws: &WorkspaceRef, json: bool) -> Result<()> {
    let req = CodeoutRequest { path: ws.vm_root.clone(), haves: Vec::new(), wip: false, max_bytes: SEED_BODY_MAX };
    let x = Exchange { api, tokens, vm_id: &target.vm_id, port: CODE_PORT, route: "POST /codeout", deadline: None, idempotent: true };
    let (reply, verdict): (DpReply<crate::wire::workspace::CodeoutManifest>, Verdict) = exchange(&x, |t| {
        let req = &req;
        async move { dp.codeout_refs(target, &t, req).await }
    })
    .await?;
    let Some(manifest) = reply.body.filter(|_| matches!(verdict, Verdict::Done)) else {
        outln!("{}: nothing to fetch", target.vm_id);
        return Ok(());
    };
    let rules = ScanSet::load(&ctx.paths, &ctx.cfg, ws)?.rules;
    let shown = |name: &str| !credential_shaped(name, &rules);
    let user = crate::gitrun::GitRun::mac(&ws.root);
    let at = |name: &str| user.output(["rev-parse", "--verify", "--quiet", name]).ok().map(|o| String::from_utf8_lossy(&o).trim().to_string());
    let mut moves = Vec::new();
    let hidden = manifest.refs.keys().filter(|r| !shown(r)).count();
    for (vm_ref, id) in manifest.refs.iter().filter(|(r, _)| shown(r)) {
        let Some(name) = box_ref_of(vm_ref) else {
            moves.push(serde_json::json!({ "vm_ref": vm_ref, "id": id, "skipped": true }));
            continue;
        };
        let now = at(&name);
        let state = match &now {
            Some(n) if n == id => "up to date",
            Some(_) => "would move",
            None => "new",
        };
        moves.push(serde_json::json!({ "vm_ref": vm_ref, "box": name, "id": id, "now": now, "state": state }));
    }
    // `null` when detached, or when the branch's name looks like a credential (its ref is then among `hidden`).
    let branch = manifest.branch.as_deref().filter(|b| shown(b));
    if json {
        let v = serde_json::json!({ "backend": ctx.backend_name(), "dry_run": true, "vm": target.vm_id, "head": manifest.head, "branch": branch, "refs": moves, "hidden": hidden });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        let on = match (manifest.branch.is_some(), branch) {
            (_, Some(b)) => format!(" on {b}"),
            (true, None) => " on a branch whose name looks like a credential".to_string(),
            (false, None) => String::new(),
        };
        outln!("box fetch --dry-run: {} (HEAD {}{on})", target.vm_id, short(&manifest.head));
        for m in &moves {
            let vm_ref = m["vm_ref"].as_str().unwrap_or_default();
            match m["box"].as_str() {
                Some(name) => outln!("  {vm_ref} -> {name}: {}", m["state"].as_str().unwrap_or_default()),
                None => outln!("  {vm_ref}: skipped (a name {BOX_REFS} keeps)"),
            }
        }
        if hidden > 0 {
            outln!("  {}", hidden_note(hidden));
        }
        outln!("nothing was fetched");
    }
    Ok(())
}
