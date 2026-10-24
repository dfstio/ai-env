//! The session commands of the transcript store (S9 plan §5, G4;
//! plans/s9-contracts.md §4.4): `session sync`, `session gc --remote`,
//! `session migrate-s9`, `session forget --purge`'s S3 half, and the sync a
//! `vm terminate` or a `vm gc` runs before it ends a VM. Every refusal that
//! needs no AWS comes before the runtime key's Touch ID; nothing here prints
//! a URL, a transcript byte or a credential.
use super::client::S3Client;
use super::manifest::{self, ORIGIN_VM};
use super::stage::{self, MacChat};
use super::sync::{SyncCtx, SyncReport};
use super::{S3Sign, S3Target, TranscriptSync};
use crate::bridge::api::{MicrovmApi, VmState};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::dataplane::{HttpsEndpoint, MintingTokens};
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::{self, SessionRow};
use crate::bridge::remote::audit_event;
use crate::bridge::scan::Rules;
use crate::bridge::view::{ViewOutcome, ViewTarget};
use crate::bridge::vm::cmd::{backend, runtime, with_backend, Ctx};
use crate::bridge::vm::registry::{self as vm_registry, RowStatus, VmRow};
use crate::bridge::vm::run;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::frame::CAP_TRANSCRIPT_S3_V1;
use std::path::{Path, PathBuf};

/// The Mac's projects directory (`<CLAUDE_CONFIG_DIR, else ~/.claude>/projects`).
fn projects() -> Result<PathBuf> {
    crate::bridge::mirror::mac_config_dir().map(|d| d.join("projects")).ok_or_else(|| CliError::Msg("neither CLAUDE_CONFIG_DIR nor HOME is set: no projects directory".into()))
}

/// The session's tripwires (the built-ins plus `[review].tripwires`): what masks its view.
fn rules_of(paths: &Paths, cfg: &BridgeConfig) -> std::result::Result<Rules, BridgeError> {
    crate::bridge::scan::load_lists(Some((paths, &cfg.review)), None, None, false).map(|(r, _)| r).map_err(BridgeError::Config)
}

/// What a registered remote session syncs with: its row's slug (the
/// child's projects directory, the VM's and this Mac's) and cwd (the view's).
pub fn row_sync(paths: &Paths, cfg: &BridgeConfig, knobs: &crate::bridge::lab::VmKnobs, row: &SessionRow, projects: &Path) -> std::result::Result<TranscriptSync, BridgeError> {
    cfg.transcript.validate()?;
    let slug = row.slug.clone().filter(|s| !s.is_empty() && !s.contains('/') && s != "." && s != "..").ok_or_else(|| BridgeError::Config(format!("session {} records no project directory (slug)", row.session_id)))?;
    let target = S3Target::resolve(paths, knobs)?;
    let proxy = match target.endpoint {
        super::S3Endpoint::Lab(_) => None,
        super::S3Endpoint::Aws => {
            let state = crate::bridge::infra::read_infra_state(paths).ok().flatten();
            let (ip, _) = crate::bridge::egress::effective_proxy_ip(cfg.aws.proxy_private_ip.as_deref(), state.as_ref());
            Some(crate::bridge::egress::proxy_url(ip, crate::bridge::egress::PROXY_PORT))
        }
    };
    Ok(TranscriptSync { target, slug, mac_cwd: row.cwd.clone().unwrap_or_default(), mac_projects: projects.to_path_buf(), proxy, view_messages: cfg.transcript.view_messages })
}

/// One sync of `sid` on the VM of `vm` (its row), the data plane through
/// the endpoint with tokens minted by `api` (in memory only).
pub async fn sync_on_vm<A: MicrovmApi + S3Sign>(ctx: &Ctx, api: &A, vm: &VmRow, sid: &str, sync: &TranscriptSync, rules: &Rules) -> std::result::Result<SyncReport, BridgeError> {
    crate::bridge::workspace::require_cap(vm.caps.as_deref().unwrap_or_default(), &vm.id, CAP_TRANSCRIPT_S3_V1)?;
    let live = api.get(&vm.id).await?;
    if live.state.is_terminal() {
        return Err(BridgeError::Terminated(format!("{} is {}", vm.id, live.state.as_str())));
    }
    let mut row = vm.clone();
    if !live.endpoint.is_empty() {
        row.endpoint = Some(live.endpoint.clone());
    }
    let target = crate::bridge::agent::AgentTarget::from_row(&row)?;
    let dp = HttpsEndpoint::new(&ctx.knobs)?;
    let tokens = MintingTokens::new(api, &ctx.paths, &vm.id, false);
    SyncCtx { api, dp: &dp, tokens: &tokens, paths: &ctx.paths, target: &target, sync, rules, deadline: None }.sync_session(sid).await
}

// ---- session sync ---------------------------------------------------------------------------------

/// `ai-env session sync UUID [--json]`: the per-turn step on demand (stat,
/// push, commit, view) on the session's VM. Refused before any Touch ID: not
/// a uuid (2); no such session, not a remote session, no VM (1); a VM whose
/// image lacks `transcript_s3_v1` (7). Then: the VM gone (8), S3 (7).
pub fn cmd_sync(store: &Keystore, uuid: &str, json: bool) -> Result<()> {
    if !registry::is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let ctx = Ctx::load()?;
    let row = registry::read(&ctx.paths, uuid)?.ok_or_else(|| CliError::Msg(format!("no session {uuid}")))?;
    if row.mode != "remote" {
        return Err(CliError::Msg(format!("session {uuid} is not a remote session (mode {}): its transcript is on this Mac", if row.mode.is_empty() { "unknown" } else { row.mode.as_str() })));
    }
    let vm_id = row.microvm_id.clone().filter(|id| vm_registry::is_vm_id(id)).ok_or_else(|| CliError::Msg(format!("session {uuid} names no VM")))?;
    let vm = vm_registry::read_row(&ctx.paths, &vm_id)?.ok_or_else(|| CliError::Msg(format!("session {uuid}'s VM {vm_id} has no row in state/vms")))?;
    if vm.status == RowStatus::Terminated {
        return Err(BridgeError::Terminated(format!("{vm_id} is terminated (its row says so)")).into());
    }
    crate::bridge::workspace::require_cap(vm.caps.as_deref().unwrap_or_default(), &vm_id, CAP_TRANSCRIPT_S3_V1)?;
    let sync = row_sync(&ctx.paths, &ctx.cfg, &ctx.knobs, &row, &projects()?)?;
    let rules = rules_of(&ctx.paths, &ctx.cfg)?;
    let rt = runtime()?;
    let report = rt.block_on(async {
        let b = backend(store, &ctx).await?;
        Ok::<_, CliError>(with_backend!(&b, |api, _ep| sync_on_vm(&ctx, api, &vm, uuid, &sync, &rules).await)?)
    })?;
    let pushed = report.pushed.as_ref().map(|p| serde_json::json!({"kind": p.kind, "from": p.from, "len": p.len, "key": p.key}));
    let view = report.view.as_ref().filter(|v| !matches!(v, ViewOutcome::Refused(_))).map(|v| {
        let (messages, masked, bytes) = v.counts();
        serde_json::json!({"messages": messages, "masked": masked, "bytes": bytes})
    });
    if json {
        let doc = serde_json::json!({"session": report.session, "vm": report.vm, "pushed": pushed, "view": view, "outcome": report.outcome()});
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        let what = report.pushed.as_ref().map_or_else(|| "S3 held it already".to_string(), |p| format!("pushed a {} of {} bytes from {} ({})", p.kind, p.len, p.from, p.key));
        let files = if report.files > 0 { format!(", {} subtree file(s)", report.files) } else { String::new() };
        let view = match &report.view {
            Some(ViewOutcome::Refused(why)) => format!("; the view was refused ({why})"),
            Some(v) => format!("; view {} ({} messages, {} masked)", v.word(), v.counts().0, v.counts().1),
            None => String::new(),
        };
        outln!("{} {} on {}: {what}{files}; {} bytes in S3{view}", report.outcome(), report.session, report.vm, report.committed);
    }
    Ok(())
}

// ---- before a VM ends -----------------------------------------------------------------------------

/// How long all of one VM's syncs before its termination may take
/// together ([`sync_before_terminate`]): a VM that accepts connections but
/// never answers would otherwise hold `vm terminate` for each session's
/// lock wait and request budgets, retries included.
pub const TERMINATE_SYNC_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// Before this Mac terminates `vm_id` itself (`vm terminate`, `vm gc`,
/// `[vm].auto_gc`): one sync of each session whose transcript is kept in S3
/// and whose row names that VM (S9), best effort, all of them within
/// [`TERMINATE_SYNC_BUDGET`]: a failure is a warning (the shim's
/// `/terminate` pushes the main transcript's tail past the committed
/// length; a subtree file changed since the last sync is lost), never a
/// refusal of the termination. Past the budget, or once the endpoint fails
/// to answer (a transport failure), no further session is tried: one
/// warning names those left. A VM that GetMicrovm finds SUSPENDED is not
/// synced, and no warning says so: a sync's first request would resume it
/// only to end it (`vm gc` never probes such a VM either). One found
/// SUSPENDING still runs its `/suspend` hook, which a termination could
/// cut: it is waited for until SUSPENDED (`run::Poll::SETTLE`, within the
/// budget; one that does not settle is a warning), and is not synced
/// either. A `/suspend` pushes the main transcript's tail past the
/// committed length through the URL the last sync or turn handed it
/// (unless it had expired: `wire::s3::TAIL_EXPIRY`), but once per
/// committed length: the tail key is written once (`If-None-Match: *`) and
/// only a sync moves it. So bytes written after the first such push, with
/// no sync since, are lost here, as is a subtree file changed since the
/// last sync. S10 (I2): a chat that moved off the VM is never synced from
/// it ([`moved_off`], logged, no warning): its copy there may be behind
/// what S3 holds, and a sync would commit that older copy as a new base,
/// rolling the manifest back. The warnings.
pub async fn sync_before_terminate<A: MicrovmApi + S3Sign>(ctx: &Ctx, api: &A, vm_id: &str) -> Vec<String> {
    let sessions: Vec<SessionRow> = registry::list(&ctx.paths)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.microvm_id.as_deref() == Some(vm_id) && (r.transcript_home.as_deref() == Some(manifest::HOME_S3) || ctx.paths.transcript_manifest(&r.session_id).exists()))
        .filter(|r| !moved_off_logged(&ctx.paths, &r.session_id, vm_id))
        .collect();
    if sessions.is_empty() {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    let (vm, projects, rules) = match (vm_registry::read_row(&ctx.paths, vm_id), projects(), rules_of(&ctx.paths, &ctx.cfg)) {
        (Ok(Some(vm)), Ok(p), Ok(r)) => (vm, p, r),
        _ => return vec![format!("{vm_id}: its sessions' transcripts were not synced before it ends (its row, the projects directory or the tripwires could not be read)")],
    };
    let until = tokio::time::Instant::now() + TERMINATE_SYNC_BUDGET;
    // GetMicrovm only for a VM whose row records the cap: one without it is each session's warning, with no AWS call.
    if vm.caps.as_deref().unwrap_or_default().iter().any(|c| c == CAP_TRANSCRIPT_S3_V1) {
        if let Ok(Ok(live)) = tokio::time::timeout_at(until, api.get(vm_id)).await {
            if matches!(live.state, VmState::Suspending | VmState::Suspended) {
                // SUSPENDING: its /suspend hook (the tail push) runs until SUSPENDED, and a termination before that could cut it.
                if live.state == VmState::Suspending {
                    let why = match tokio::time::timeout_at(until, run::wait_for_state(api, vm_id, &VmState::Suspended, ctx.poll(run::Poll::SETTLE))).await {
                        Ok(Ok(_)) => None,
                        Ok(Err(e)) => Some(e.to_string()),
                        Err(_) => Some(format!("still SUSPENDING after {} s", TERMINATE_SYNC_BUDGET.as_secs())),
                    };
                    if let Some(why) = why {
                        return vec![format!("{vm_id}: the transcript tails its /suspend pushes may not have gone up before it ends ({why})")];
                    }
                }
                tracing::info!(vm = vm_id, found = live.state.as_str(), sessions = sessions.len(), "transcripts not synced before the VM ends: a request would resume it; a /suspend pushed their tails, once per committed length");
                return Vec::new();
            }
        }
    }
    let sync_one = |row: SessionRow| {
        let (vm, projects, rules) = (&vm, &projects, &rules);
        async move {
            // S10 (I2): read again at its turn: a move may have taken the chat off this VM since the listing.
            if moved_off_logged(&ctx.paths, &row.session_id, vm_id) {
                return Ok(SyncReport { session: row.session_id.clone(), vm: vm_id.to_string(), pushed: None, files: 0, view: None, committed: 0 });
            }
            let sync = row_sync(&ctx.paths, &ctx.cfg, &ctx.knobs, &row, projects)?;
            sync_on_vm(ctx, api, vm, &row.session_id, &sync, rules).await
        }
    };
    warnings.extend(sync_each_within(vm_id, sessions, until, sync_one).await);
    warnings
}

/// S10 (I2): why the chat `sid` is no longer synced from `vm_id` before that
/// VM ends, if it is not: its row no longer names the VM (gone, or a move
/// pointed it elsewhere), or the last commit of its transcript came from
/// another VM (`Manifest.vm`: the chat moved, and the VM it moved to
/// committed since). Either way the copy on `vm_id` may be behind what S3
/// holds. A row or a manifest that cannot be read is no reason: the sync
/// runs and says what failed.
#[must_use]
pub fn moved_off(paths: &Paths, sid: &str, vm_id: &str) -> Option<String> {
    match registry::read(paths, sid) {
        Ok(Some(row)) if row.microvm_id.as_deref() != Some(vm_id) => return Some(format!("its row names {} now", row.microvm_id.as_deref().unwrap_or("no VM"))),
        Ok(None) => return Some("its row is gone".to_string()),
        _ => {}
    }
    match manifest::read(paths, sid) {
        Ok(Some(m)) => m.vm.filter(|committer| committer != vm_id).map(|committer| format!("its transcript was last committed from {committer}")),
        _ => None,
    }
}

/// [`moved_off`], its reason logged: whether the chat is left alone.
fn moved_off_logged(paths: &Paths, sid: &str, vm_id: &str) -> bool {
    let why = moved_off(paths, sid, vm_id);
    if let Some(why) = &why {
        tracing::info!(session = sid, vm = vm_id, "transcript not synced before the VM ends: {why} (the copy there may be behind S3's)");
    }
    why.is_some()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod i2_tests {
    use super::*;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::bridge::s3::manifest::{Manifest, ManifestPart};

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const VM: &str = "microvm-00000000-0000-4000-8000-000000000001";
    const OTHER: &str = "microvm-00000000-0000-4000-8000-000000000002";

    /// The session's row naming `vm`, its transcript kept in S3.
    fn row_on(paths: &Paths, vm: Option<&str>) {
        let row = SessionRow { session_id: SID.into(), mode: "remote".into(), microvm_id: vm.map(str::to_string), transcript_home: Some(manifest::HOME_S3.into()), slug: Some("-w".into()), ..SessionRow::default() };
        registry::write(paths, &row).unwrap();
    }

    /// The session's manifest, its last commit from `committer` (none: never a VM's).
    fn committed_by(paths: &Paths, committer: Option<&str>) {
        let target = crate::bridge::s3::S3Target { bucket: crate::bridge::s3::LAB_BUCKET.into(), owner: crate::bridge::s3::LAB_OWNER.into(), endpoint: crate::bridge::s3::S3Endpoint::Aws };
        let mut m = Manifest::new(SID, &target, manifest::ORIGIN_VM, &format!("-w/{SID}.jsonl"), "2026-10-20T10:15:30.000Z");
        m.parts.push(ManifestPart { key: format!("v1/{SID}/vm/g1/b"), version_id: "v1".into(), from: 0, len: 10, sha256: "a".repeat(64), encoding: None, stored_len: None, stored_sha256: None });
        (m.gen, m.committed, m.vm) = (1, 10, committer.map(str::to_string));
        manifest::write(paths, &m).unwrap();
    }

    /// A chat is synced from the VM its row names and last committed from
    /// (or that no VM committed yet); it is left alone once its row names
    /// another VM or none, or is gone, or once another VM committed it.
    #[test]
    fn moved_off_reads_the_row_then_the_manifests_committer() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        assert_eq!(moved_off(&paths, SID, VM).as_deref(), Some("its row is gone"));
        row_on(&paths, Some(VM));
        assert_eq!(moved_off(&paths, SID, VM), None, "no manifest yet");
        committed_by(&paths, None);
        assert_eq!(moved_off(&paths, SID, VM), None, "no VM committed it yet (a chat staged from the Mac)");
        committed_by(&paths, Some(VM));
        assert_eq!(moved_off(&paths, SID, VM), None, "this VM committed it last");
        committed_by(&paths, Some(OTHER));
        assert_eq!(moved_off(&paths, SID, VM).as_deref(), Some(format!("its transcript was last committed from {OTHER}").as_str()));
        committed_by(&paths, Some(VM));
        row_on(&paths, Some(OTHER));
        assert_eq!(moved_off(&paths, SID, VM).as_deref(), Some(format!("its row names {OTHER} now").as_str()));
        row_on(&paths, None);
        assert_eq!(moved_off(&paths, SID, VM).as_deref(), Some("its row names no VM now"));
    }

    /// Before a VM ends, a chat whose row still names it but whose
    /// transcript another VM committed last is never synced from it: no
    /// warning, no AWS call (the VM's row is not even read). Without the
    /// guard the session is taken, and its missing VM row is a warning.
    #[tokio::test]
    async fn a_chat_another_vm_committed_is_never_synced_from_this_one() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = Ctx { paths: Paths::from_root_and_env(tmp.path().join("bridge"), None), cfg: BridgeConfig::default(), knobs: crate::bridge::lab::VmKnobs::default() };
        let api = FakeMicrovmApi::new();
        row_on(&ctx.paths, Some(VM));
        committed_by(&ctx.paths, Some(OTHER));
        assert_eq!(sync_before_terminate(&ctx, &api, VM).await, Vec::<String>::new());
        assert!(api.calls().is_empty(), "{:?}", api.calls());
        committed_by(&ctx.paths, Some(VM));
        let w = sync_before_terminate(&ctx, &api, VM).await;
        assert!(w.len() == 1 && w[0].contains("not synced before it ends"), "this VM committed it: taken (its VM row is missing here): {w:?}");
    }
}

/// [`sync_before_terminate`]'s loop: `sync_one` of each of `sessions` in
/// turn, all by `until`. A failure is a warning naming its session; past
/// `until`, or after a transport failure (`BridgeError::Endpoint`: the
/// endpoint does not answer, the next session's would not either), one
/// warning names every session not synced, and none is tried after it.
pub async fn sync_each_within<F, Fut>(vm_id: &str, sessions: Vec<SessionRow>, until: tokio::time::Instant, sync_one: F) -> Vec<String>
where
    F: Fn(SessionRow) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<SyncReport, BridgeError>>,
{
    let mut warnings = Vec::new();
    let ids: Vec<String> = sessions.iter().map(|r| r.session_id.clone()).collect();
    let budget = TERMINATE_SYNC_BUDGET.as_secs();
    for (i, row) in sessions.into_iter().enumerate() {
        let sid = row.session_id.clone();
        let left = || ids[i..].join(", ");
        match tokio::time::timeout_at(until, sync_one(row)).await {
            Err(_) => {
                warnings.push(format!("{vm_id}: the transcripts of {} were not synced within {budget} s before it ends; their tails go up at /terminate", left()));
                break;
            }
            Ok(Ok(r)) => tracing::info!(session = %sid, vm = vm_id, outcome = r.outcome(), "transcript synced before the VM ends"),
            Ok(Err(e @ BridgeError::Endpoint(_))) => {
                warnings.push(format!("{vm_id}: the transcripts of {} were not synced before it ends ({e}); their tails go up at /terminate", left()));
                break;
            }
            Ok(Err(e)) => warnings.push(format!("{vm_id}: the transcript of {sid} was not synced before it ends ({e}); its tail goes up at /terminate")),
        }
    }
    warnings
}

// ---- session gc --remote --------------------------------------------------------------------------

/// One session `session gc --remote` would remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcCandidate {
    pub session: String,
    pub objects: usize,
    pub bytes: u64,
    pub at: String,
    /// The view's rel under the projects directory.
    pub view_rel: String,
}

/// The sessions whose transcript S3 keeps (a manifest) whose registry row is
/// closed or absent, and whose manifest was last written more than
/// `older_than_days` days before `now` (Unix seconds); oldest first. A
/// session whose objects S3 may hold with no manifest (an upload or a
/// first sync cut before its manifest: `state/transcripts/<sid>/`, or its
/// lock file, alone) counts too once that trace is older than the horizon:
/// its objects unknown (0), its view the row's.
pub fn gc_candidates(paths: &Paths, older_than_days: u32, now: u64) -> std::result::Result<Vec<GcCandidate>, BridgeError> {
    let mut out = Vec::new();
    let dir = paths.transcripts();
    let Ok(entries) = std::fs::read_dir(&dir) else { return Ok(out) };
    let horizon = now.saturating_sub(u64::from(older_than_days) * 86_400);
    for e in entries.flatten() {
        let file = e.file_name().to_string_lossy().into_owned();
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        let name = match file.strip_suffix(".lock") {
            Some(sid) if !is_dir => sid.to_string(),
            _ if is_dir => file.clone(),
            _ => continue,
        };
        if !registry::is_uuid(&name) || out.iter().any(|c: &GcCandidate| c.session == name) {
            continue;
        }
        let row = registry::read(paths, &name).ok().flatten();
        let closed = row.as_ref().is_none_or(|r| r.status == "closed");
        match manifest::read(paths, &name)? {
            Some(m) => {
                let at = crate::wire::time::parse_rfc3339_utc(&m.at).unwrap_or(0);
                if closed && at < horizon {
                    let objects = m.parts.len() + m.files.len() + m.superseded.len();
                    out.push(GcCandidate { session: name, objects, bytes: m.committed + m.files.iter().map(|f| f.len).sum::<u64>(), at: m.at.clone(), view_rel: m.rel.clone() });
                }
            }
            None => {
                // No manifest: what a cut upload or first sync left, dated by its own trace. A directory holding only
                // `origin/` is what a gc already left (a Mac-begun chat's original): no trace of S3 objects.
                let lock = std::fs::symlink_metadata(paths.transcript_lock(&name)).is_ok();
                let traced = lock || std::fs::read_dir(paths.transcript_dir(&name)).is_ok_and(|d| d.flatten().any(|x| x.file_name() != "origin"));
                let mtime = e.metadata().ok().and_then(|md| md.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(now, |d| d.as_secs());
                if traced && closed && mtime < horizon {
                    let view_rel = row.and_then(|r| r.view).unwrap_or_default();
                    out.push(GcCandidate { session: name, objects: 0, bytes: 0, at: crate::wire::time::rfc3339_utc(mtime), view_rel });
                }
            }
        }
    }
    out.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.session.cmp(&b.session)));
    Ok(out)
}

/// Delete every current object under `v1/<sid>/` (delete markers; the old
/// versions expire after 30 days): how many.
pub async fn delete_session_objects<S: S3Sign>(client: &S3Client<'_, S>, sid: &str) -> std::result::Result<usize, BridgeError> {
    let listed = client.list(&format!("{}{sid}/", crate::wire::s3::KEY_PREFIX)).await?;
    for o in &listed {
        client.delete(&o.key).await?;
    }
    Ok(listed.len())
}

/// Remove the view of `rel` (`<slug>/<sid>.jsonl`) under `projects`, only
/// when it is one (never a transcript): whether it went.
pub fn remove_view(projects: &Path, rel: &str) -> bool {
    let path = projects.join(rel);
    crate::bridge::view::is_view_file(&path) && std::fs::remove_file(&path).is_ok()
}

/// `state/transcripts/<sid>/` but its `origin/` (a Mac-begun chat's original
/// is kept), and the session's lock file: whether anything went.
fn remove_state_but_origin(paths: &Paths, sid: &str) -> bool {
    let mut removed = false;
    if let Ok(entries) = std::fs::read_dir(paths.transcript_dir(sid)) {
        for e in entries.flatten() {
            if e.file_name() == "origin" {
                continue;
            }
            let p = e.path();
            removed |= if e.file_type().is_ok_and(|t| t.is_dir()) { std::fs::remove_dir_all(&p).is_ok() } else { std::fs::remove_file(&p).is_ok() };
        }
    }
    let _ = std::fs::remove_dir(paths.transcript_dir(sid));
    let _ = std::fs::remove_file(paths.transcript_lock(sid));
    removed
}

/// `session gc --remote --yes`'s removal through `client`: for each of
/// `candidates`, under its manifest lock, its objects' current versions
/// deleted ([`delete_session_objects`]), then `state/transcripts/<sid>/`
/// but its `origin/` (a Mac-begun chat's original is kept) and its lock
/// file, then its view under `projects` (only a view: never a transcript).
/// The objects removed.
pub async fn gc_remove<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, candidates: &[GcCandidate], projects: Option<&Path>) -> std::result::Result<usize, BridgeError> {
    let mut n = 0usize;
    for c in candidates {
        let _held = manifest::lock(paths, &c.session).await?;
        n += delete_session_objects(client, &c.session).await?;
        remove_state_but_origin(paths, &c.session);
        if let Some(p) = projects.filter(|_| !c.view_rel.is_empty()) {
            remove_view(p, &c.view_rel);
        }
    }
    Ok(n)
}

/// `ai-env session gc --remote [--older-than DAYS] [--yes] [--json]`: the
/// candidates ([`gc_candidates`]); with `--yes` their objects' current
/// versions deleted, then their manifests and views (a Mac-begun chat's
/// `origin/` is kept), audited `transcript_gc`. Without `--yes` nothing is
/// read in S3 and no Touch ID is asked. Exits: 0; 5 no runtime key; 7 S3.
pub fn cmd_gc(store: &Keystore, older_than: u32, yes: bool, json: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let candidates = gc_candidates(&paths, older_than, crate::wire::time::unix_now())?;
    let mut removed_objects = 0usize;
    if yes && !candidates.is_empty() {
        let ctx = Ctx::load()?;
        let target = S3Target::resolve(&ctx.paths, &ctx.knobs)?;
        let projects = projects().ok();
        let rt = runtime()?;
        removed_objects = rt.block_on(async {
            let b = backend(store, &ctx).await?;
            let n = with_backend!(&b, |api, _ep| {
                let client = S3Client::new(api, &target)?;
                gc_remove(&client, &ctx.paths, &candidates, projects.as_deref()).await?
            });
            Ok::<_, CliError>(n)
        })?;
        let pairs = [("sessions", candidates.len().to_string()), ("objects", removed_objects.to_string()), ("older_than_days", older_than.to_string())];
        crate::bridge::workspace::audit(&paths, audit_event::TRANSCRIPT_GC, &pairs);
    }
    if json {
        let sessions: Vec<serde_json::Value> = candidates.iter().map(|c| serde_json::json!({"session": c.session, "objects": c.objects, "bytes": c.bytes, "at": c.at})).collect();
        let doc = serde_json::json!({"dry_run": !yes, "older_than_days": older_than, "sessions": sessions, "removed_objects": removed_objects});
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else if candidates.is_empty() {
        outln!("no S3 transcript of a session closed more than {older_than} days ago");
    } else {
        for c in &candidates {
            outln!("{}  {} objects, {} bytes, last written {}", c.session, c.objects, c.bytes, c.at);
        }
        if yes {
            outln!("removed {removed_objects} object(s) of {} session(s) (their old versions expire after 30 days)", candidates.len());
        } else {
            outln!("nothing removed: add --yes to remove these {} session(s)' transcripts from S3", candidates.len());
        }
    }
    Ok(())
}

// ---- session forget --purge -------------------------------------------------------------------------

/// `session forget UUID --purge`'s S3 half (after `registry::forget_check`):
/// when this Mac keeps any trace of the session's transcript store (its
/// manifest, `state/transcripts/<sid>/`, its lock file, a registry row
/// naming `transcript_home` or `origin`: S3 may hold its objects without a
/// manifest, an upload or a first sync cut before it), every current
/// object under `v1/<sid>/` is deleted with the runtime key (a Touch ID),
/// then `state/transcripts/<sid>/` whole (`origin/` included) and the lock
/// file, then the view (only a view: never a transcript). Whether anything
/// went. [`forget_purge_many`] of the one session.
pub fn forget_purge(store: &Keystore, paths: &Paths, sid: &str) -> std::result::Result<bool, BridgeError> {
    Ok(forget_purge_many(store, paths, &[sid.to_string()])?.first().copied().unwrap_or(false))
}

/// S10 (F1): `session forget UUID... --purge`'s S3 half for several
/// sessions (once `registry::forget_check` passed for each): [`forget_purge`]
/// of each, in their order, with one unseal of the runtime key for all of
/// them (one Touch ID, asked only when one of them left a trace
/// ([`s3_traces`]); S9 asked one per session). Each view's rel is read
/// before its manifest goes. A non-uuid is refused before anything; a
/// failure of one session's purge ends it there (the sessions purged before
/// it stay purged, the command's forget of every row is not reached).
/// Whether each removed anything.
pub fn forget_purge_many(store: &Keystore, paths: &Paths, sids: &[String]) -> std::result::Result<Vec<bool>, BridgeError> {
    if let Some(bad) = sids.iter().find(|sid| !registry::is_uuid(sid)) {
        return Err(BridgeError::Config(format!("not a session id: {bad:?}")));
    }
    let rels: Vec<Option<String>> = sids.iter().map(|sid| manifest::read(paths, sid).ok().flatten().map(|m| m.rel).or_else(|| registry::read(paths, sid).ok().flatten().and_then(|r| r.view))).collect();
    let traced: Vec<bool> = sids.iter().map(|sid| s3_traces(paths, sid)).collect();
    let mut removed = vec![false; sids.len()];
    if traced.contains(&true) {
        let ctx = Ctx::load().map_err(BridgeError::Cli)?;
        let target = S3Target::resolve(paths, &ctx.knobs)?;
        let rt = runtime().map_err(BridgeError::Cli)?;
        removed = rt.block_on(async {
            let b = backend(store, &ctx).await.map_err(BridgeError::Cli)?;
            with_backend!(&b, |api, _ep| {
                let client = S3Client::new(api, &target)?;
                let mut purged = Vec::with_capacity(sids.len());
                for (sid, traced) in sids.iter().zip(&traced) {
                    purged.push(*traced && purge_with(&client, paths, sid).await?);
                }
                Ok::<_, BridgeError>(purged)
            })
        })?;
    }
    if let Ok(p) = projects() {
        for (removed, rel) in removed.iter_mut().zip(rels) {
            if let Some(rel) = rel {
                *removed |= remove_view(&p, &rel);
            }
        }
    }
    Ok(removed)
}

/// Whether this Mac keeps a trace of `sid` in the transcript store, so
/// `forget --purge` asks S3 ([`forget_purge`]): its manifest,
/// `state/transcripts/<sid>/`, its lock file (every sync and upload takes
/// it), or a registry row naming `transcript_home` or `origin`.
#[must_use]
pub fn s3_traces(paths: &Paths, sid: &str) -> bool {
    matches!(manifest::read(paths, sid), Ok(Some(_)))
        || std::fs::symlink_metadata(paths.transcript_dir(sid)).is_ok_and(|md| md.is_dir())
        || std::fs::symlink_metadata(paths.transcript_lock(sid)).is_ok()
        || registry::read(paths, sid).ok().flatten().is_some_and(|r| r.transcript_home.is_some() || r.origin.is_some())
}

/// [`forget_purge`]'s S3 half through `client`: under the session's
/// manifest lock every current object under `v1/<sid>/` deleted
/// ([`delete_session_objects`]), then `state/transcripts/<sid>/` whole
/// (`origin/` included) and the lock file. Whether anything went.
pub async fn purge_with<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str) -> std::result::Result<bool, BridgeError> {
    if !registry::is_uuid(sid) {
        return Err(BridgeError::Config(format!("not a session id: {sid:?}")));
    }
    let deleted = {
        let _held = manifest::lock(paths, sid).await?;
        delete_session_objects(client, sid).await?
    };
    let mut removed = deleted > 0;
    let dir = paths.transcript_dir(sid);
    if std::fs::symlink_metadata(&dir).is_ok_and(|md| md.is_dir()) {
        std::fs::remove_dir_all(&dir).map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot remove {}: {e}", dir.display()))))?;
        removed = true;
    }
    let _ = std::fs::remove_file(paths.transcript_lock(sid));
    Ok(removed)
}

// ---- session migrate-s9 ---------------------------------------------------------------------------

/// One S8 remote chat whose copy on this Mac is the mirror (not a view).
#[derive(Debug, Clone)]
pub struct Mirror {
    pub row: SessionRow,
    /// The mirror's project directory and files (`locate`).
    pub chat: MacChat,
    /// The row's VM, when its row says it may run (not terminated).
    pub vm: Option<VmRow>,
}

impl Mirror {
    /// The VM this mirror's migration syncs from (`live_vm`) as the rows
    /// tell: the row's VM when its row says it may run (not terminated) and
    /// its caps name `transcript_s3_v1`. An S8 image's VM (without the cap)
    /// never is, running or not: its mirror goes up from this Mac, as a gone
    /// VM's does (`gone_vm`). The one rule of the dry run's list (no AWS
    /// call) and of [`migrate_one`], which then asks GetMicrovm too: only a
    /// VM that ended since its row was written is listed `live_vm` and
    /// migrated `gone_vm`.
    #[must_use]
    pub fn live_vm(&self) -> Option<&VmRow> {
        self.vm.as_ref().filter(|vm| vm.status != RowStatus::Terminated && vm.caps.as_deref().unwrap_or_default().iter().any(|c| c == CAP_TRANSCRIPT_S3_V1))
    }
}

/// The remote sessions whose copy on this Mac is S8's mirror: each row that
/// the one predicate calls one (`manifest::origin_of` is `s8_mirror`: mode
/// `remote`, no manifest, no `transcript_home`; contracts §5.3, X54) with a
/// slug whose `<mirror root, else projects>/<slug>/<sid>.jsonl` is a
/// transcript, not a view (newest first, as the registry lists them). An S9
/// chat whose Mac file is not a view (a view that could not be built, an
/// upload cut short, a view that lost its mark) is never one: its
/// transcript is in S3 already.
pub fn mirrors(paths: &Paths, projects: &Path) -> std::result::Result<Vec<Mirror>, BridgeError> {
    let mut out = Vec::new();
    for row in registry::list(paths)? {
        if row.mode != "remote" || manifest::origin_of(paths, &row.session_id) != Some(manifest::ORIGIN_S8_MIRROR) {
            continue;
        }
        let Some(slug) = row.slug.clone() else { continue };
        let root = row.mirror_root.as_deref().map_or_else(|| projects.to_path_buf(), PathBuf::from);
        let Some(chat) = stage::locate(&root, &[slug.as_str()], &row.session_id, stage::STAGE_MAX)? else { continue };
        if chat.slug != slug || crate::bridge::view::is_view_file(&chat.main_path(&row.session_id)) {
            continue;
        }
        let vm = row.microvm_id.as_deref().and_then(|id| vm_registry::read_row(paths, id).ok().flatten()).filter(|v| v.status != RowStatus::Terminated);
        out.push(Mirror { row, chat, vm });
    }
    Ok(out)
}

/// What one migration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrated {
    pub session: String,
    pub vm: Option<String>,
    /// `live_vm` or `gone_vm`.
    pub from: &'static str,
    pub bytes: u64,
    /// `migrated`, `would_migrate`, `skipped` or `failed`.
    pub outcome: &'static str,
    pub why: Option<String>,
}

/// Remove a mirror's files (the transcript and its subtree) from the projects directory.
pub(crate) fn delete_mirror(chat: &MacChat, sid: &str) -> std::result::Result<(), BridgeError> {
    for (rel, _) in &chat.files {
        let p = chat.dir.join(rel);
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot remove {}: {e}", p.display())))),
        }
    }
    let sub = chat.dir.join(sid);
    if std::fs::symlink_metadata(&sub).is_ok_and(|m| m.is_dir()) {
        let _ = std::fs::remove_dir_all(&sub);
    }
    Ok(())
}

/// The view of a mirror built on this Mac (`build`, the strict checks of
/// `bridge::view`, its tripwires masking it) and written in the mirror's
/// place once the mirror went (`gone`: deleted, or moved to `origin/`).
#[allow(clippy::too_many_arguments)]
fn view_from_mirror(paths: &Paths, m: &Mirror, sid: &str, projects: &Path, n: u32, rules: &Rules, build: stage::ViewBuilder<'_>, gone: impl FnOnce() -> std::result::Result<(), BridgeError>) -> std::result::Result<ViewOutcome, BridgeError> {
    let tail = stage::tail_of(&m.chat.main_path(sid))?;
    let reply = build(&tail, n).map_err(BridgeError::Config)?;
    gone()?;
    let target = ViewTarget { mac_projects: projects, slug: &m.chat.slug, session_id: sid, mac_cwd: m.row.cwd.as_deref().unwrap_or_default() };
    let outcome = crate::bridge::view::write_view(&target, &reply, n, rules)?;
    super::sync::audit_view(paths, sid, m.vm.as_ref().map_or("-", |v| v.id.as_str()), &outcome);
    Ok(outcome)
}

/// The migration of one mirror (`session migrate-s9 --yes`): a live VM's
/// session synced to S3 from the VM, the mirror deleted, the VM's view
/// written; a gone VM's mirror scanned, then uploaded as
/// `v1/<sid>/mac/<sha256>` (a manifest of a VM-begun chat whose first part is
/// that object), the view built here, the mirror deleted. A gone VM's mirror
/// with a finding is not uploaded: its view (built here, masked) takes its
/// place and the mirror moves to `origin/` (`skipped`, naming the finding
/// and `ai-env session forget <sid> --purge`).
#[allow(clippy::too_many_arguments)]
pub async fn migrate_one<A: MicrovmApi + S3Sign>(ctx: &Ctx, api: &A, target: &S3Target, m: &Mirror, projects: &Path, rules: &Rules, build: stage::ViewBuilder<'_>) -> Migrated {
    let sid = m.row.session_id.clone();
    let bytes = m.chat.bytes();
    let n = ctx.cfg.transcript.view_messages;
    // Only an S8 mirror (no manifest, no transcript_home): an S9 chat's copy here is never uploaded over its
    // manifest, nor deleted (a Mac-begun chat's original is kept in origin/).
    let s9 = match manifest::read(&ctx.paths, &sid) {
        Ok(Some(found)) => Some(format!("its transcript is in S3 already (a manifest, origin {}): not an S8 mirror; nothing uploaded or deleted", found.origin)),
        Ok(None) if m.row.transcript_home.is_some() => Some("its transcript is kept in S3 (transcript_home): not an S8 mirror; nothing uploaded or deleted".to_string()),
        Ok(None) => None,
        Err(e) => Some(format!("{e}: nothing uploaded or deleted")),
    };
    if let Some(why) = s9 {
        let pairs = [("session", sid.clone()), ("from", "gone_vm".to_string()), ("outcome", "failed".to_string()), ("bytes", bytes.to_string())];
        crate::bridge::workspace::audit(&ctx.paths, audit_event::TRANSCRIPT_MIGRATE, &pairs);
        return Migrated { session: sid, vm: m.vm.as_ref().map(|v| v.id.clone()), from: "gone_vm", bytes, outcome: "failed", why: Some(why) };
    }
    let live = match m.live_vm() {
        Some(vm) => api.get(&vm.id).await.ok().filter(|l| !l.state.is_terminal()).map(|_| vm.clone()),
        None => None,
    };
    let result: std::result::Result<(&'static str, &'static str, Option<String>), BridgeError> = async {
        if let Some(vm) = &live {
            let sync = row_sync(&ctx.paths, &ctx.cfg, &ctx.knobs, &m.row, projects)?;
            sync_on_vm(ctx, api, vm, &sid, &sync, rules).await?;
            delete_mirror(&m.chat, &sid)?;
            // The VM's view, now that the mirror is gone (the sync's own write found the mirror in its place).
            let dp = HttpsEndpoint::new(&ctx.knobs)?;
            let tokens = MintingTokens::new(api, &ctx.paths, &vm.id, false);
            let agent = crate::bridge::agent::AgentTarget::from_row(vm)?;
            SyncCtx { api, dp: &dp, tokens: &tokens, paths: &ctx.paths, target: &agent, sync: &sync, rules, deadline: None }.write_view(&sid, &super::sync::main_rel(&sync.slug, &sid)).await?;
            return Ok(("live_vm", "migrated", None));
        }
        let scanned = {
            let (rules_set, chat) = (crate::bridge::scan::load_lists(Some((&ctx.paths, &ctx.cfg.review)), None, None, false).map(|(r, _)| r).map_err(BridgeError::Config)?, m.chat.clone());
            crate::bridge::workspace::blocking(move || stage::scan_chat(&rules_set, &chat, crate::wire::s3::MULTIPART_PART)).await?
        };
        match scanned {
            Err(BridgeError::WorkspaceRefused { message, .. }) => {
                let first = message.lines().next().unwrap_or_default().to_string();
                view_from_mirror(&ctx.paths, m, &sid, projects, n, rules, build, || stage::move_to_origin(&ctx.paths, &sid, &m.chat).map(|_| ()))?;
                Ok(("gone_vm", "skipped", Some(format!("{first}: not uploaded; its view replaced it and the mirror is kept in {} (ai-env session forget {sid} --purge removes it)", ctx.paths.transcript_origin(&sid).display()))))
            }
            Err(e) => Err(e),
            Ok(digests) => {
                let client = S3Client::new(api, target)?;
                let at = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
                {
                    // Under the manifest's lock from before the upload: a manifest that appeared meanwhile (a sync of
                    // the chat elsewhere) is never replaced by this one.
                    let _held = manifest::lock(&ctx.paths, &sid).await?;
                    if manifest::read(&ctx.paths, &sid)?.is_some() {
                        return Err(BridgeError::Config(format!("{sid}: a manifest appeared before the upload: not an S8 mirror any more; nothing uploaded or deleted")));
                    }
                    // S11 (C.3.7): S8's legacy path stays identity.
                    let mut up = stage::upload_chat(&client, &ctx.paths, &sid, &m.chat, &digests, crate::wire::s3::MULTIPART_PART, &at, None).await?;
                    up.manifest.origin = ORIGIN_VM.to_string();
                    manifest::write(&ctx.paths, &up.manifest)?;
                }
                view_from_mirror(&ctx.paths, m, &sid, projects, n, rules, build, || delete_mirror(&m.chat, &sid))?;
                Ok(("gone_vm", "migrated", None))
            }
        }
    }
    .await;
    let (from, outcome, why) = match result {
        Ok(r) => r,
        Err(e) => (if live.is_some() { "live_vm" } else { "gone_vm" }, "failed", Some(e.to_string())),
    };
    let pairs = [("session", sid.clone()), ("from", from.to_string()), ("outcome", outcome.to_string()), ("bytes", bytes.to_string())];
    crate::bridge::workspace::audit(&ctx.paths, audit_event::TRANSCRIPT_MIGRATE, &pairs);
    Migrated { session: sid, vm: m.vm.as_ref().map(|v| v.id.clone()), from, bytes, outcome, why }
}

/// The dry run's entry for `m` (`session migrate-s9` without `--yes`; no
/// AWS call): `would_migrate`, from `live_vm` when [`Mirror::live_vm`] names
/// its VM (the rule [`migrate_one`] takes), else `gone_vm`.
#[must_use]
pub fn would_migrate(m: &Mirror) -> Migrated {
    let from = if m.live_vm().is_some() { "live_vm" } else { "gone_vm" };
    Migrated { session: m.row.session_id.clone(), vm: m.vm.as_ref().map(|v| v.id.clone()), from, bytes: m.chat.bytes(), outcome: "would_migrate", why: None }
}

/// `ai-env session migrate-s9 [--yes] [--json]` (the module doc of
/// [`migrate_one`]): without `--yes` the mirrors and what each would take
/// ([`would_migrate`]), no AWS call, no Touch ID. Exits: 0; 9 a finding
/// (that session skipped, the rest go on: 9 at the end); 5 no runtime key;
/// 7 S3 (a failed session is reported, and the exit is 7 at the end).
pub fn cmd_migrate_s9(store: &Keystore, yes: bool, json: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let projects = projects()?;
    let found = mirrors(&paths, &projects)?;
    let done: Vec<Migrated> = if yes && !found.is_empty() {
        let ctx = Ctx::load()?;
        ctx.cfg.transcript.validate()?;
        let target = S3Target::resolve(&ctx.paths, &ctx.knobs)?;
        let rules = rules_of(&ctx.paths, &ctx.cfg)?;
        let rt = runtime()?;
        rt.block_on(async {
            let b = backend(store, &ctx).await?;
            let mut out = Vec::new();
            with_backend!(&b, |api, _ep| {
                for m in &found {
                    out.push(migrate_one(&ctx, api, &target, m, &projects, &rules, &crate::wire::view::build_view).await);
                }
            });
            Ok::<_, CliError>(out)
        })?
    } else {
        found.iter().map(would_migrate).collect()
    };
    if json {
        let sessions: Vec<serde_json::Value> = done.iter().map(|d| serde_json::json!({"session": d.session, "vm": d.vm, "from": d.from, "bytes": d.bytes, "outcome": d.outcome, "why": d.why})).collect();
        let doc = serde_json::json!({"dry_run": !yes, "sessions": sessions});
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else if done.is_empty() {
        outln!("no S8 mirror of a remote chat on this Mac");
    } else {
        for d in &done {
            let why = d.why.as_deref().map_or_else(String::new, |w| format!(": {w}"));
            outln!("{}  {} ({}, {} bytes){why}", d.session, d.outcome, d.from, d.bytes);
        }
        if !yes {
            outln!("nothing migrated: add --yes to move these {} chat(s) to S3", done.len());
        }
    }
    if done.iter().any(|d| d.outcome == "skipped") {
        return Err(CliError::Policy(format!("session migrate-s9: {} chat(s) skipped for a finding (above)", done.iter().filter(|d| d.outcome == "skipped").count())));
    }
    if done.iter().any(|d| d.outcome == "failed") {
        return Err(CliError::Aws(format!("session migrate-s9: {} chat(s) failed (above)", done.iter().filter(|d| d.outcome == "failed").count())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::FakeMicrovmApi;

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const VM: &str = "microvm-00000000-0000-4000-8000-000000000001";

    /// Before this Mac ends a VM (`vm terminate`, `vm gc`): nothing for a VM
    /// no S3 session names; a session whose VM
    /// row is missing, or whose VM lacks `transcript_s3_v1`, is a warning
    /// naming it (the tail goes up at /terminate), never a refusal, and no
    /// AWS call is made for either.
    #[tokio::test]
    async fn sync_before_terminate_is_best_effort_and_needs_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = Ctx { paths: Paths::from_root_and_env(tmp.path().join("bridge"), None), cfg: BridgeConfig::default(), knobs: crate::bridge::lab::VmKnobs::default() };
        let api = FakeMicrovmApi::new();
        assert!(sync_before_terminate(&ctx, &api, VM).await.is_empty(), "no session names the VM");
        let row = SessionRow { session_id: SID.into(), mode: "remote".into(), microvm_id: Some(VM.into()), transcript_home: Some(manifest::HOME_S3.into()), slug: Some("-w".into()), ..SessionRow::default() };
        registry::write(&ctx.paths, &row).unwrap();
        let w = sync_before_terminate(&ctx, &api, VM).await;
        assert!(w.len() == 1 && w[0].contains("not synced before it ends"), "no VM row: {w:?}");
        let vm = VmRow { id: VM.into(), status: RowStatus::Running, caps: Some(vec!["credential_cache".into(), "workspace_v1".into()]), ..VmRow::default() };
        vm_registry::write_row(&ctx.paths, &vm).unwrap();
        let w = sync_before_terminate(&ctx, &api, VM).await;
        assert!(w.len() == 1 && w[0].contains("make infra-status WRITE=1"), "no transcripts bucket recorded: {w:?}");
        let state = crate::bridge::infra::InfraState {
            stack: "dev".into(),
            region: "eu-central-1".into(),
            account_id: Some("123456789012".into()),
            transcripts_bucket: Some("ai-env-transcripts-123456789012".into()),
            ..crate::bridge::infra::InfraState::default()
        };
        crate::bridge::registry::ensure_private_dir(ctx.paths.infra_state().parent().unwrap()).unwrap();
        std::fs::write(ctx.paths.infra_state(), toml::to_string(&state).unwrap()).unwrap();
        let w = sync_before_terminate(&ctx, &api, VM).await;
        assert!(w.len() == 1 && w[0].contains(SID) && w[0].contains(CAP_TRANSCRIPT_S3_V1) && w[0].contains("its tail goes up at /terminate"), "{w:?}");
        assert!(api.calls().is_empty(), "no AWS call: {:?}", api.calls());
    }

    /// A session kept in S3 whose row names VM, VM's row recording
    /// `transcript_s3_v1`, the bucket recorded, polls scaled to 10 ms a
    /// second; and the fake control plane with VM in `state`.
    fn asleep_world(root: &Path, state: VmState) -> (Ctx, FakeMicrovmApi) {
        use crate::bridge::api::VmInfo;
        let knobs = crate::bridge::lab::VmKnobs { backoff_ms: Some(10), ..crate::bridge::lab::VmKnobs::default() };
        let ctx = Ctx { paths: Paths::from_root_and_env(root.join("bridge"), None), cfg: BridgeConfig::default(), knobs };
        let row = SessionRow { session_id: SID.into(), mode: "remote".into(), microvm_id: Some(VM.into()), transcript_home: Some(manifest::HOME_S3.into()), slug: Some("-w".into()), ..SessionRow::default() };
        registry::write(&ctx.paths, &row).unwrap();
        let caps = Some(vec!["credential_cache".into(), "workspace_v1".into(), CAP_TRANSCRIPT_S3_V1.into()]);
        let vm = VmRow { id: VM.into(), status: RowStatus::Suspended, caps, endpoint: Some("vm.example.invalid".into()), session_token: Some("t".repeat(64)), ..VmRow::default() };
        vm_registry::write_row(&ctx.paths, &vm).unwrap();
        let infra = crate::bridge::infra::InfraState {
            stack: "dev".into(),
            region: "eu-central-1".into(),
            account_id: Some("123456789012".into()),
            transcripts_bucket: Some("ai-env-transcripts-123456789012".into()),
            ..crate::bridge::infra::InfraState::default()
        };
        crate::bridge::registry::ensure_private_dir(ctx.paths.infra_state().parent().unwrap()).unwrap();
        std::fs::write(ctx.paths.infra_state(), toml::to_string(&infra).unwrap()).unwrap();
        let api = FakeMicrovmApi::new();
        api.insert_vm(VmInfo {
            id: VM.into(),
            state,
            endpoint: "vm.example.invalid".into(),
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            started_at_unix: Some(1_760_000_000),
            max_duration_s: 3600,
            state_reason: None,
            execution_role_arn: None,
            idle: None,
            ingress: Vec::new(),
            egress: Vec::new(),
            terminated_at_unix: None,
        });
        (ctx, api)
    }

    /// S9 round 5 (R1): a VM that GetMicrovm finds SUSPENDED is not synced
    /// before this Mac ends it: a sync's first request would resume it. Its
    /// `/suspend` pushed the main transcript's tail past the committed
    /// length, once per committed length (bytes written after that push,
    /// with no sync since, are lost). One GetMicrovm, then nothing (no
    /// endpoint token, no resume), and no warning.
    #[tokio::test]
    async fn a_suspended_vm_is_not_woken_to_sync_before_it_ends() {
        use crate::bridge::api::Call;
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, api) = asleep_world(tmp.path(), VmState::Suspended);
        let w = sync_before_terminate(&ctx, &api, VM).await;
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(api.calls(), [Call::Get(VM.into())], "one GetMicrovm, then nothing");
    }

    /// S9 round 5 (F1): a VM still SUSPENDING runs its `/suspend` hook (the
    /// tail push) until it is SUSPENDED, and a termination could cut it. So
    /// it is waited for first, then not synced either: GetMicrovm alone, no
    /// token, no warning, and the VM is SUSPENDED by the time the step
    /// returns. One that never settles is one warning naming it, and still
    /// GetMicrovm alone.
    #[tokio::test]
    async fn a_suspending_vm_is_waited_for_and_not_woken() {
        use crate::bridge::api::Call;
        let only_gets = |calls: &[Call]| calls.len() >= 2 && calls.iter().all(|c| *c == Call::Get(VM.into()));
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, api) = asleep_world(tmp.path(), VmState::Suspending);
        // The platform: SUSPENDED once a GetMicrovm saw the VM SUSPENDING.
        let settle = async {
            while api.calls().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            api.set_state(VM, VmState::Suspended);
        };
        let ending = async {
            let w = sync_before_terminate(&ctx, &api, VM).await;
            (w, api.state().vms.get(VM).map(|v| v.state.clone()))
        };
        let ((w, at_return), ()) = tokio::join!(ending, settle);
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(at_return, Some(VmState::Suspended), "returned before the VM settled");
        assert!(only_gets(&api.calls()), "{:?}", api.calls());
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, api) = asleep_world(tmp.path(), VmState::Suspending);
        let w = sync_before_terminate(&ctx, &api, VM).await;
        assert!(w.len() == 1 && w[0].starts_with(VM) && w[0].contains("may not have gone up") && w[0].contains("last state SUSPENDING"), "{w:?}");
        assert!(only_gets(&api.calls()), "{:?}", api.calls());
    }

    /// S9 phase 4 (R1): one VM's syncs before its termination are bounded
    /// together. A sync that never answers ends the loop at the deadline
    /// with one warning naming every session left (the next one never
    /// tried); a transport failure ends it at once the same way; any other
    /// failure is that session's warning and the next goes on.
    #[tokio::test]
    async fn the_syncs_before_a_termination_are_bounded_together() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let row = |n: u8| SessionRow { session_id: format!("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a{n:02x}"), ..SessionRow::default() };
        let rows = || vec![row(1), row(2), row(3)];
        let tried = AtomicU32::new(0);
        let t = tokio::time::Instant::now();
        let w = sync_each_within(VM, rows(), t + std::time::Duration::from_millis(200), |_| {
            tried.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<std::result::Result<SyncReport, BridgeError>>()
        })
        .await;
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
        assert_eq!((w.len(), tried.load(Ordering::SeqCst)), (1, 1), "{w:?}");
        assert!(w[0].contains(&row(1).session_id) && w[0].contains(&row(3).session_id) && w[0].contains("not synced within 60 s"), "{w:?}");
        let tried = AtomicU32::new(0);
        let w = sync_each_within(VM, rows(), tokio::time::Instant::now() + TERMINATE_SYNC_BUDGET, |r| {
            let n = tried.fetch_add(1, Ordering::SeqCst);
            async move {
                match n {
                    0 => Err(BridgeError::Config(format!("no slug for {}", r.session_id))),
                    _ => Err(BridgeError::Endpoint("connection refused".into())),
                }
            }
        })
        .await;
        assert_eq!((w.len(), tried.load(Ordering::SeqCst)), (2, 2), "{w:?}");
        assert!(w[0].contains(&row(1).session_id) && !w[0].contains(&row(2).session_id), "{w:?}");
        assert!(w[1].contains(&format!("{}, {}", row(2).session_id, row(3).session_id)) && w[1].contains("connection refused"), "{w:?}");
    }
}
