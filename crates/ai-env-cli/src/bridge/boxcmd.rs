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
//!
//! S9 (G2): `box fetch --smart-http` reaches the VM through git smart-HTTP
//! v2 (`codeout::fetch_smart_http`; the VM must name `git_http_v1`), into
//! the same import; `box fetch --dry-run` mints its token without recording
//! it in the VM's row, and reads no `/health` (its caps are the row's); a
//! fetch says once per workspace that its repository has no ai-env pre-push
//! hook.
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
// S9 (G2): `box fetch --smart-http`.
use crate::bridge::codeout::{fetch_smart_http, Via};
use crate::bridge::gitsmart::{manifest_of, Client};

const MIB: u64 = 1024 * 1024;

/// `ai-env box …` (S9: `review`, `hook-install` and `fetch --smart-http`).
pub fn main(store: &Keystore, cmd: BoxCmd) -> Result<()> {
    match cmd {
        BoxCmd::Seed { workspace, branch, no_wip, replace, dry_run, max_mib, json } => seed(store, &Seed { workspace, branch, no_wip, replace, dry_run, max_mib, json }),
        BoxCmd::Fetch { target, wip, dry_run, max_mib, smart_http, json } => fetch_cmd(store, target.as_deref(), wip, dry_run, max_mib, smart_http, json),
        BoxCmd::Review { rev, base, repo, json, pre_push } => crate::bridge::review::cmd_review(rev.as_deref(), &base, repo.as_deref(), json, pre_push.as_deref()),
        BoxCmd::HookInstall { repo, dry_run, json } => crate::bridge::review::cmd_hook_install(repo.as_deref(), dry_run, json),
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

/// `box fetch [SESSION or WORKSPACE] [--wip] [--dry-run] [--max-mib N] [--smart-http] [--json]`.
/// A fetch (not a dry run) first notes, once per workspace, a repository
/// without the ai-env pre-push hook ([`note_missing_hook`]), before any
/// Touch ID.
fn fetch_cmd(store: &Keystore, target: Option<&str>, wip: bool, dry_run: bool, max_mib: Option<u32>, smart_http: bool, json: bool) -> Result<()> {
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
    if !dry_run {
        note_missing_hook(&ctx.paths, &ws);
    }
    let flags = Fetch { opts: FetchOpts { wip, max_bytes }, dry_run, via: if smart_http { Via::SmartHttp } else { Via::Codeout }, json };
    let rt = runtime()?;
    rt.block_on(async {
        match backend(store, &ctx).await? {
            Backend::Sdk(api, ep) => fetch_on(&ctx, api, &*ep, &ws, vm.as_deref(), &flags).await,
            Backend::Fake(f) => fetch_on(&ctx, Arc::new(f.clone()), &f, &ws, vm.as_deref(), &flags).await,
        }
    })
}

/// `box fetch`'s flags past its target.
struct Fetch {
    opts: FetchOpts,
    dry_run: bool,
    /// `POST /codeout`, or git smart-HTTP (`--smart-http`).
    via: Via,
    json: bool,
}

/// `box fetch`'s note, once per workspace (S9 §4.2, L7): the workspace's
/// repository has no ai-env pre-push hook where git runs hooks
/// (`review::hook_state` says missing), so a push from it is not reviewed.
/// The workspace row's `hook_noted_at` records that it was said. A foreign
/// hook is doctor's to name (it may chain the review), an unknown state
/// says nothing. Best effort: a row that cannot be written costs a warning.
fn note_missing_hook(paths: &Paths, ws: &WorkspaceRef) {
    use crate::bridge::review::{hook_state, HookState};
    use crate::bridge::workspace::rows;
    if rows::row_of(paths, ws).ok().flatten().is_some_and(|row| row.hook_noted_at.is_some()) {
        return;
    }
    if !matches!(hook_state(&ws.root), HookState::Missing(_)) {
        return;
    }
    let root = ws.root.display();
    voice::note(&format!("the workspace {root} has no ai-env pre-push hook: ai-env box hook-install {root} installs it"));
    if let Err(e) = rows::update(paths, ws, |row| row.hook_noted_at = Some(crate::wire::time::unix_now())) {
        voice::warn(&format!("the workspace row of {} was not written: {e}", ws.cwd.display()));
    }
}

/// `box fetch` from the session's or the workspace's VM: its caps first
/// (`workspace_v1`; with `--smart-http` also `git_http_v1`, exit 7 naming
/// `make deploy` before any request of the fetch), then the dry run, or the
/// fetch through the flags' way (`codeout::fetch`, `codeout::fetch_smart_http`).
/// A dry run takes only the caps its row records: reading `/health` mints a
/// recorded token and rewrites the row, so a row without them is refused
/// (exit 1), nothing minted.
async fn fetch_on<A: MicrovmApi + 'static, E: EndpointClient>(ctx: &Ctx, api: Arc<A>, ep: &E, ws: &WorkspaceRef, vm: Option<&str>, flags: &Fetch) -> Result<()> {
    let row = match vm {
        Some(id) => read_row(&ctx.paths, id)?.ok_or_else(|| BridgeError::VmNotFound(format!("{id} (the session's VM) has no row")))?,
        None => workspace_vm(&ctx.paths, &*api, ws).await?,
    };
    if flags.dry_run && row.caps.is_none() {
        return Err(BridgeError::Config(format!("{} has no capabilities on record, and reading its /health would write its row, which a dry run never does (ai-env vm health {} records them)", row.id, row.id)).into());
    }
    let caps = caps_of(ctx, &*api, ep, &row).await?;
    crate::bridge::workspace::require_capability(&caps, &row.id)?;
    if flags.via == Via::SmartHttp {
        crate::bridge::workspace::require_cap(&caps, &row.id, crate::wire::frame::CAP_GIT_HTTP_V1)?;
    }
    let target = AgentTarget::from_row(&row)?;
    let dp = HttpsEndpoint::new(&ctx.knobs)?;
    let tokens = MintingTokens::new(api.clone(), &ctx.paths, &row.id, false);
    if flags.dry_run {
        // A dry run changes nothing on the Mac: not even its token's expiry in the VM's row.
        return fetch_dry_run(ctx, &*api, &dp, &tokens.unrecorded(), &target, ws, flags).await;
    }
    let cctx = CodeoutCtx { api: api.clone(), dp: Arc::new(dp), tokens: Arc::new(tokens), paths: ctx.paths.clone(), cfg: Arc::new(ctx.cfg.clone()), target, ws: ws.clone(), capture_settings: false, transcript: None };
    let report = match flags.via {
        Via::Codeout => fetch(&cctx, flags.opts).await?,
        Via::SmartHttp => fetch_smart_http(&cctx, flags.opts).await?,
    };
    if flags.json {
        let v = serde_json::json!({ "backend": ctx.backend_name(), "vm": row.id, "via": flags.via.word(), "report": report });
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

/// `box fetch --dry-run`: the VM's refs against `refs/remotes/box/*`, read
/// the way the fetch would reach them, nothing transferred: a code-out's
/// manifest without its pack and without a snapshot (`POST /codeout`), or
/// with `--smart-http` the advertisement and `ls-refs` (`gitsmart`), never a
/// `fetch` (so a ref naming a tree or a blob, which only the pack tells from
/// a commit, is listed there). Its tokens are `unrecorded` ones (the VM's
/// row stays as it was).
async fn fetch_dry_run<A: MicrovmApi>(ctx: &Ctx, api: &A, dp: &HttpsEndpoint, tokens: &MintingTokens<Arc<A>>, target: &AgentTarget, ws: &WorkspaceRef, flags: &Fetch) -> Result<()> {
    let manifest = match flags.via {
        Via::Codeout => codeout_manifest(api, dp, tokens, target, ws).await?,
        Via::SmartHttp => {
            let crate::bridge::workspace::WsKind::Git { object_format, .. } = &ws.kind;
            let client = Client { api, tokens, git: dp, target };
            let advert = client.advertise(*object_format).await?;
            Some(manifest_of(&client.ls_refs(&advert).await?, advert.object_format)?)
        }
    };
    let Some(manifest) = manifest else {
        outln!("{}: nothing to fetch", target.vm_id);
        return Ok(());
    };
    print_dry_run(ctx, target, ws, &manifest, flags)
}

/// The VM's refs as `POST /codeout` gives them, read only to its manifest
/// line (`HttpsEndpoint::codeout_refs`: no snapshot, the pack never read);
/// `None` when the VM has nothing to fetch (204).
async fn codeout_manifest<A: MicrovmApi>(api: &A, dp: &HttpsEndpoint, tokens: &MintingTokens<Arc<A>>, target: &AgentTarget, ws: &WorkspaceRef) -> Result<Option<crate::wire::workspace::CodeoutManifest>> {
    let req = CodeoutRequest { path: ws.vm_root.clone(), haves: Vec::new(), wip: false, max_bytes: SEED_BODY_MAX, manifest_when_empty: false };
    let x = Exchange { api, tokens, vm_id: &target.vm_id, port: CODE_PORT, cap: crate::wire::frame::CAP_WORKSPACE_V1, route: "POST /codeout", deadline: None, idempotent: true };
    let (reply, verdict): (DpReply<crate::wire::workspace::CodeoutManifest>, Verdict) = exchange(&x, |t| {
        let req = &req;
        async move { dp.codeout_refs(target, &t, req).await }
    })
    .await?;
    Ok(reply.body.filter(|_| matches!(verdict, Verdict::Done)))
}

/// What `box fetch --dry-run` prints of `manifest`: each VM ref and its box
/// name, new, moving or up to date. A name that looks like a credential
/// (`codeout::credential_shaped`, the scans' rules), a ref's or the
/// checked-out branch's, is never printed: such refs are only counted, as a
/// fetch keeps them out.
fn print_dry_run(ctx: &Ctx, target: &AgentTarget, ws: &WorkspaceRef, manifest: &crate::wire::workspace::CodeoutManifest, flags: &Fetch) -> Result<()> {
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
    if flags.json {
        let v = serde_json::json!({ "backend": ctx.backend_name(), "dry_run": true, "via": flags.via.word(), "vm": target.vm_id, "head": manifest.head, "branch": branch, "refs": moves, "hidden": hidden });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        let on = match (manifest.branch.is_some(), branch) {
            (_, Some(b)) => format!(" on {b}"),
            (true, None) => " on a branch whose name looks like a credential".to_string(),
            (false, None) => String::new(),
        };
        let command = match flags.via {
            Via::Codeout => "box fetch --dry-run",
            Via::SmartHttp => "box fetch --smart-http --dry-run",
        };
        outln!("{command}: {} (HEAD {}{on})", target.vm_id, short(&manifest.head));
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

#[cfg(test)]
mod g2_tests {
    use super::*;
    use crate::bridge::workspace::{Head, WsKind};
    use crate::wire::workspace::ObjectFormat;

    fn git(dir: &Path, args: &[&str]) {
        let o = std::process::Command::new("git").args(args).current_dir(dir).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    }

    /// The workspace of `dir` (a repository there, its hooks where git runs
    /// them by default: the repository's own `core.hooksPath` beats this
    /// user's global one), its rows under `slug`.
    fn workspace(dir: &Path, slug: &str, hook: Option<&str>) -> WorkspaceRef {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q", "-b", "main"]);
        git(dir, &["config", "core.hooksPath", ".git/hooks"]);
        if let Some(body) = hook {
            std::fs::create_dir_all(dir.join(".git/hooks")).unwrap();
            std::fs::write(dir.join(".git/hooks/pre-push"), body).unwrap();
        }
        let kind = WsKind::Git { git_dir: dir.join(".git"), common_dir: dir.join(".git"), object_format: ObjectFormat::Sha1 };
        WorkspaceRef { cwd: dir.to_path_buf(), root: dir.to_path_buf(), vm_cwd: dir.display().to_string(), vm_root: dir.display().to_string(), slug: slug.into(), kind, head: Head::Detached { sha: "a".repeat(40) }, seed_branch: None }
    }

    /// S9: the missing-hook note is recorded once per workspace, and the
    /// next fetch keeps the record as it was (it says nothing more); a
    /// repository with ai-env's hook, or with a foreign one, is never noted,
    /// and no row is written for it.
    #[test]
    fn the_missing_hook_note_is_recorded_once_and_for_a_missing_hook_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let paths = Paths::from_root_and_env(root.join("bridge"), None);
        let noted = |ws: &WorkspaceRef| crate::bridge::workspace::rows::row_of(&paths, ws).unwrap().and_then(|r| r.hook_noted_at);
        let missing = workspace(&root.join("missing"), "-missing", None);
        note_missing_hook(&paths, &missing);
        let at = noted(&missing).expect("noted, and recorded");
        note_missing_hook(&paths, &missing);
        assert_eq!(noted(&missing), Some(at), "once");
        let ours = format!("#!/bin/sh\n{}\nexit 0\n", crate::bridge::review::PRE_PUSH_MARK);
        for (name, hook) in [("ours", ours.as_str()), ("foreign", "#!/bin/sh\nexit 0\n")] {
            let ws = workspace(&root.join(name), &format!("-{name}"), Some(hook));
            note_missing_hook(&paths, &ws);
            assert!(crate::bridge::workspace::rows::row_of(&paths, &ws).unwrap().is_none(), "{name}: no row written");
        }
    }
}
