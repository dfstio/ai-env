//! The resume's transcript upload (S8 §8): before a `--resume` spawn, the
//! Mac's mirror of the session (`seed::candidates` and its transcript files,
//! the S2 seeder's rules) goes to the VM's projects directory through
//! `GET`/`PUT /transcript`, only when the VM's copy is absent, shorter or
//! different at equal length; a longer VM copy wins (409 `vm_longer`). At
//! most `remote::TRANSCRIPT_MAX`. Built in S8 wave 1 (W4).
//!
//! What goes up is scanned first, as the seed is (S8 phase 4, review
//! CUSTODY-2): a chat holds whatever its tools printed, on the Mac (before
//! S8, under the kill switch, as a local child) or, mirrored, on a VM. Each
//! file the upload may send is read once, its first `len` bytes, through the
//! seed's tripwires (`blobscan::ScanSet`), its name too; a clean one is
//! copied into a private directory under `state/tmp/` (`transcript-<pid>-*`,
//! 0700, the copies 0600, removed with the upload) and the `PUT` sends that
//! copy: exactly the bytes the scan read, whatever the Mac's file does
//! meanwhile, and a file with a hit is written nowhere. A name that trips a
//! rule refuses the whole upload before its first request (the rel rides
//! every request); a hit in a file's bytes refuses it before its first `PUT`
//! when the VM's copy of that file is absent, shorter or different at equal
//! length. A file the VM holds already, the same or longer, is never sent,
//! so what it holds is no finding: a chat reopened on the VM it ran on goes
//! on (review F2-R1). The refusal is `WorkspaceRefused { finding }` (exit 9)
//! naming `transcript:REL`, the line and the rule, never a value, audited
//! `seed_refused` (step `transcript`). The wrapper's P1 runs the scan beside
//! the Touch ID when the session names no VM of its own ([`scan_mac_copy`]:
//! any finding refuses, so it starts no VM); [`ensure`] scans again what it
//! sends (to a VM the session named, a resume miss's retry, a file that
//! changed since).
use super::blobscan::{finding_lines, shown_path, Finding, ScanSet};
use super::{audit, blocking, code, require_capability, EnsureCtx, TranscriptOutcome, WorkspaceRef};
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::dataplane::{exchange, DataPlane, Exchange, TokenSource, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::ensure_private_dir;
use crate::bridge::remote::audit_event;
use crate::bridge::seed::{candidates, transcript_files};
use crate::wire::workspace::{refusal, transcript_rel_check, TranscriptWrite, APP_PORT};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// One file of the Mac's copy as the scan read it: its rel below the
/// session's project directory (`rel_in`) and under the VM's slug (`rel`),
/// its length, the sha256 of the bytes read, the tripwires' hits in them
/// (a refusal only if the file is to be sent), and their private copy,
/// which the `PUT` sends (`None`: P1's scan keeps none, a file with a hit
/// has none).
struct Scanned {
    rel_in: String,
    rel: String,
    len: u64,
    sha: String,
    hits: Vec<Finding>,
    copy: Option<PathBuf>,
}

/// The Mac's copy of a session as the upload sends it: its files in the
/// listing's order, how many it skipped (no transcript rel names them: never
/// read, never sent), and the copies' directory, removed with them when dropped.
struct MacCopy {
    files: Vec<Scanned>,
    skipped: u32,
    _copies: Option<tempfile::TempDir>,
}

/// The directory one upload's copies go to (`state/tmp/transcript-<pid>-*`,
/// 0700), removed with them when dropped; one a process left when it exited
/// under it goes with the next seed's sweep of `state/tmp/`.
fn copies_dir(paths: &Paths) -> Result<tempfile::TempDir, BridgeError> {
    let tmp = paths.tmp();
    ensure_private_dir(&tmp)?;
    let dir = tempfile::Builder::new()
        .prefix(&format!("transcript-{}-", std::process::id()))
        .tempdir_in(&tmp)
        .map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot create a scratch directory in {}: {e}", tmp.display()))))?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// `path`'s first `len` bytes, read once (a regular file, `O_NOFOLLOW`: one
/// swapped for a symlink since the listing is never read through it) and
/// run through `set`'s tripwires: their sha256, and the `(line, rule)` of
/// every hit, never a value. Clean, they are written to `copy` when given
/// (created new, 0600); a hit is written nowhere. A file shorter than `len`
/// now is an error.
fn read_scanned(set: &ScanSet, path: &Path, len: u64, copy: Option<&Path>) -> Result<(String, Vec<(usize, String)>), BridgeError> {
    use sha2::{Digest, Sha256};
    let at = |what: &str, p: &Path, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", p.display())));
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|e| at("open", path, e))?;
    if !file.metadata().map_err(|e| at("stat", path, e))?.is_file() {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is not a regular file", path.display()))));
    }
    let mut bytes = Vec::new();
    file.take(len).read_to_end(&mut bytes).map_err(|e| at("read", path, e))?;
    if bytes.len() as u64 != len {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is shorter than its {len} bytes now", path.display()))));
    }
    let mut hits = set.rules.scan_bytes(&bytes);
    hits.sort();
    if let Some(copy) = copy.filter(|_| hits.is_empty()) {
        let mut out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(copy).map_err(|e| at("create", copy, e))?;
        out.write_all(&bytes).map_err(|e| at("write", copy, e))?;
    }
    Ok((hex::encode(Sha256::digest(&bytes)), hits))
}

/// The Mac's newest copy of `session_id` (the first of `seed::candidates`
/// under `mirror_root` for `slugs`, its files as `seed::transcript_files`
/// lists them) as the upload sends it under `vm_slug`, every file through
/// `set` ([`read_scanned`]: its hits kept with it), its name too (the rel
/// rides every request and names the VM's file: one that trips a rule is a
/// finding, shown as `blobscan::PATH_NAME`); with `paths`, each clean one
/// copied into a directory of its `state/tmp/` ([`copies_dir`]). A file no
/// transcript rel admits is skipped, never read: it is never sent.
/// `Ok(None)`: the Mac holds no copy. A name's finding is
/// `WorkspaceRefused { finding }` (`transcript:REL: rule R`, at most
/// `blobscan::FINDINGS_MAX` lines) once every file was read; the copies go
/// with it. A hit in a file's bytes is its caller's to refuse
/// ([`scan_mac_copy`] any, [`upload`] one it would send).
fn scan_copy(set: &ScanSet, mirror_root: &Path, slugs: &[&str], session_id: &str, vm_slug: &str, paths: Option<&Paths>) -> Result<Option<MacCopy>, BridgeError> {
    let Some(dir) = candidates(mirror_root, slugs, session_id).into_iter().next() else { return Ok(None) };
    let listed = transcript_files(&dir, session_id)?;
    if listed.is_empty() {
        return Ok(None);
    }
    let copies = paths.map(copies_dir).transpose()?;
    let (mut files, mut skipped, mut named) = (Vec::new(), 0u32, Vec::new());
    for (n, (rel_in, len)) in listed.into_iter().enumerate() {
        let rel = format!("{vm_slug}/{rel_in}");
        if transcript_rel_check(&rel).is_err() {
            skipped += 1;
            continue;
        }
        let location = format!("transcript:{}", shown_path(set, &rel_in));
        let finding = |(line, rule): (usize, String)| Finding { location: location.clone(), object: None, line, rule, key: None };
        named.extend(set.rules.scan_bytes(rel_in.as_bytes()).into_iter().map(|(_, rule)| finding((0, rule))));
        let copy = copies.as_ref().map(|d| d.path().join(n.to_string()));
        let (sha, hits) = read_scanned(set, &dir.join(&rel_in), len, copy.as_deref())?;
        let copy = copy.filter(|_| hits.is_empty());
        files.push(Scanned { rel_in, rel, len, sha, hits: hits.into_iter().map(finding).collect(), copy });
    }
    if !named.is_empty() {
        return Err(refused(&named));
    }
    Ok(Some(MacCopy { files, skipped, _copies: copies }))
}

/// The refusal `findings` make: `WorkspaceRefused { finding }` (exit 9),
/// one line each ([`finding_lines`]).
fn refused(findings: &[Finding]) -> BridgeError {
    BridgeError::WorkspaceRefused { code: code::FINDING, message: finding_lines(findings) }
}

/// `e`, a refusal of the transcript, audited `seed_refused` (step
/// `transcript`, the VM once one was chosen) on its way out.
fn audited(paths: &Paths, ws: &WorkspaceRef, vm: Option<&str>, e: BridgeError) -> BridgeError {
    if let BridgeError::WorkspaceRefused { code, .. } = &e {
        let mut pairs = vec![("workspace", ws.cwd.display().to_string()), ("code", (*code).to_string()), ("step", "transcript".to_string())];
        pairs.extend(vm.map(|v| ("vm", v.to_string())));
        audit(paths, audit_event::SEED_REFUSED, &pairs);
    }
    e
}

/// P1's scan of a `--resume`'s transcript (the wrapper's, on the snapshot's
/// blocking thread beside the Touch ID, for a session that names no VM of
/// its own, so none known to hold the chat): the Mac's copy as [`ensure`]
/// would send it under `vm_slug`, every file and name through the seed's
/// tripwires (`ScanSet::load`: the built-ins, and `[review].tripwires` when
/// that file exists), nothing copied, nothing sent. Any finding refuses the
/// session before any VM is chosen (`WorkspaceRefused { finding }`, exit 9,
/// audited `seed_refused`); no Mac copy, or a clean one, is `Ok`.
pub(crate) fn scan_mac_copy(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, mirror_root: &Path, slugs: &[&str], session_id: &str, vm_slug: &str) -> Result<(), BridgeError> {
    let set = ScanSet::load(paths, cfg, ws)?;
    let found = scan_copy(&set, mirror_root, slugs, session_id, vm_slug, None).map_err(|e| audited(paths, ws, None, e))?;
    let hits: Vec<Finding> = found.iter().flat_map(|c| &c.files).flat_map(|f| f.hits.iter().cloned()).collect();
    if hits.is_empty() {
        return Ok(());
    }
    Err(audited(paths, ws, None, refused(&hits)))
}

/// [`super::ensure_transcript`]: each file of the Mac's newest copy of the
/// session (the first of `seed::candidates`) under `vm_slug`, scanned and
/// copied first ([`scan_copy`]: a name's finding refuses before any
/// request), then stat'ed, and its copy put when the VM's copy is absent,
/// shorter, or of the same length but other bytes ([`upload`]: a hit in a
/// file to put refuses before the first `PUT`); the VM's answer must hold
/// exactly the bytes sent.
pub(crate) async fn ensure<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &EnsureCtx<'_, A, D, T>, mirror_root: &Path, slugs: &[&str], session_id: &str, vm_slug: &str) -> Result<TranscriptOutcome, BridgeError> {
    require_capability(ctx.caps, &ctx.target.vm_id)?;
    let found = {
        let (paths, cfg, ws) = (ctx.paths.clone(), ctx.cfg.clone(), ctx.ws.clone());
        let (root, slugs, id, vm_slug) = (mirror_root.to_path_buf(), slugs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(), session_id.to_string(), vm_slug.to_string());
        blocking(move || -> Result<Option<MacCopy>, BridgeError> {
            let refs: Vec<&str> = slugs.iter().map(String::as_str).collect();
            let set = ScanSet::load(&paths, &cfg, &ws)?;
            scan_copy(&set, &root, &refs, &id, &vm_slug, Some(&paths))
        })
        .await?
        .map_err(|e| audited(ctx.paths, ctx.ws, Some(&ctx.target.vm_id), e))?
    };
    let outcome = match &found {
        Some(copy) => upload(ctx, copy, session_id).await?,
        None => TranscriptOutcome::NoMacCopy,
    };
    let (files, bytes) = match &outcome {
        TranscriptOutcome::Uploaded { files, bytes } => (*files, *bytes),
        _ => (0, 0),
    };
    audit(ctx.paths, audit_event::TRANSCRIPT_PUT, &[("vm", ctx.target.vm_id.clone()), ("outcome", outcome.word().into()), ("files", files.to_string()), ("bytes", bytes.to_string())]);
    Ok(outcome)
}

/// [`ensure`]'s requests: every file of `copy` stat'ed first. One the VM
/// holds the same, or longer, is never sent, and its hits are no finding
/// (the VM holds those bytes already). A hit in any other refuses them all
/// before the first `PUT` (`WorkspaceRefused { finding }`, audited
/// `seed_refused` with the VM); else each goes up as its copy.
async fn upload<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &EnsureCtx<'_, A, D, T>, copy: &MacCopy, session_id: &str) -> Result<TranscriptOutcome, BridgeError> {
    let main = format!("{session_id}.jsonl");
    let (mut uploaded, mut bytes) = (0u32, 0u64);
    let mut longer: Option<(u64, u64)> = None;
    let stat_x = Exchange { api: ctx.api, tokens: ctx.tokens, vm_id: &ctx.target.vm_id, port: APP_PORT, route: "GET /transcript", deadline: ctx.deadline, idempotent: true };
    let mut due = Vec::new();
    for file in &copy.files {
        let rel = &file.rel;
        let stat = match exchange(&stat_x, |t| async move { ctx.dp.transcript_stat(ctx.target, &t, rel).await }).await? {
            (reply, Verdict::Done) => reply.body.ok_or_else(|| BridgeError::Protocol("GET /transcript answered without a stat".into()))?,
            (reply, _) => return Err(BridgeError::Protocol(format!("GET /transcript answered HTTP {} where a stat was due", reply.status))),
        };
        if stat.present && stat.size > file.len {
            if file.rel_in == main {
                longer = Some((stat.size, file.len));
            }
            continue;
        }
        if stat.present && stat.size == file.len && stat.sha256.as_deref() == Some(file.sha.as_str()) {
            continue;
        }
        due.push(file);
    }
    let hits: Vec<Finding> = due.iter().flat_map(|f| f.hits.iter().cloned()).collect();
    if !hits.is_empty() {
        return Err(audited(ctx.paths, ctx.ws, Some(&ctx.target.vm_id), refused(&hits)));
    }
    let put_x = Exchange { route: "PUT /transcript", idempotent: false, ..stat_x };
    for file in due {
        let (rel, len, sha) = (&file.rel, file.len, file.sha.as_str());
        let body = file.copy.as_deref().ok_or_else(|| BridgeError::Io(std::io::Error::other(format!("{rel}: the scan kept no copy to send"))))?;
        let answer = exchange(&put_x, |t| async move { ctx.dp.put_transcript(ctx.target, &t, rel, body, len).await }).await?;
        match answer {
            (reply, Verdict::Done) => {
                let r = reply.body.ok_or_else(|| BridgeError::Protocol("PUT /transcript answered without a reply".into()))?;
                if r.sha256 != sha || r.size != len {
                    return Err(BridgeError::WorkspaceFailed { code: refusal::CHANGED, message: format!("{rel}: the VM's copy is not the {len} bytes sent: reopen the chat to send it again") });
                }
                if r.outcome == TranscriptWrite::Written {
                    uploaded += 1;
                    bytes += len;
                }
            }
            (_, Verdict::VmLonger { size }) => {
                if file.rel_in == main {
                    longer = Some((size.unwrap_or(0), len));
                }
            }
            (reply, _) => return Err(BridgeError::Protocol(format!("PUT /transcript answered HTTP {} where an upload's answer was due", reply.status))),
        }
    }
    if copy.skipped > 0 {
        tracing::info!("transcript: {} file(s) of {session_id} skipped: no transcript rel names them", copy.skipped);
    }
    Ok(match longer {
        Some((vm, mac)) => TranscriptOutcome::VmLonger { vm, mac },
        None if uploaded > 0 => TranscriptOutcome::Uploaded { files: uploaded, bytes },
        None => TranscriptOutcome::AlreadyThere,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::agent::AgentTarget;
    use crate::bridge::api::{AuthToken, FakeMicrovmApi};
    use crate::bridge::dataplane::{CodeoutBody, DpReply};
    use crate::bridge::workspace::{Head, SeedLimits, SeedProgress, WsKind};
    use crate::wire::frame::CAP_WORKSPACE_V1;
    use crate::wire::redact::Secret;
    use crate::wire::workspace::{CodeoutRequest, ObjectFormat, SeedQuery, SeedReply, SeedState, SettingsCapture, TranscriptReply, TranscriptStat};
    use std::sync::Mutex;

    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// An AWS access key id's shape, built at run time.
    fn key() -> String {
        format!("{}{}", "AKIA", "Q".repeat(16))
    }

    /// A local chat's two lines: a prompt, then what a tool printed.
    fn lines(printed: &str) -> String {
        format!("{{\"type\":\"user\",\"message\":{{\"content\":\"show the deploy config\"}}}}\n{{\"type\":\"user\",\"message\":{{\"content\":[{{\"type\":\"tool_result\",\"content\":\"{printed}\"}}]}}}}\n")
    }

    /// A bridge under a tempdir, a workspace at `/w`, and the Mac's projects
    /// root (`<tmp>/projects`), the session's project `-mac`.
    struct World {
        _tmp: tempfile::TempDir,
        paths: Paths,
        cfg: BridgeConfig,
        ws: WorkspaceRef,
        projects: PathBuf,
    }

    impl World {
        fn new() -> World {
            let tmp = tempfile::tempdir().unwrap();
            let ws = WorkspaceRef {
                cwd: "/w".into(),
                root: "/w".into(),
                vm_cwd: "/w".into(),
                vm_root: "/w".into(),
                slug: "-w".into(),
                kind: WsKind::Git { git_dir: "/w/.git".into(), common_dir: "/w/.git".into(), object_format: ObjectFormat::Sha1 },
                head: Head::Detached { sha: "a".repeat(40) },
                seed_branch: None,
            };
            World { paths: Paths::from_root_and_env(tmp.path().join("bridge"), None), cfg: BridgeConfig::default(), ws, projects: tmp.path().join("projects"), _tmp: tmp }
        }

        /// `rel` below the session's project, holding `text`.
        fn plant(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.projects.join("-mac").join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }

        /// The audit's rows of `event`.
        fn rows(&self, event: &str) -> Vec<serde_json::Value> {
            let text = std::fs::read_to_string(self.paths.audit()).unwrap_or_default();
            text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
        }

        /// What is left in `state/tmp/`.
        fn tmp_left(&self) -> Vec<String> {
            std::fs::read_dir(self.paths.tmp()).map(|d| d.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default()
        }
    }

    fn target() -> AgentTarget {
        AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false }
    }

    /// The finding a refusal names (its message), or a panic naming what came instead.
    fn finding(e: BridgeError) -> String {
        match e {
            BridgeError::WorkspaceRefused { code: code::FINDING, message } => message,
            other => panic!("not a finding: {other:?}"),
        }
    }

    /// A VM's data plane holding `held` (rel, size, sha256) and nothing
    /// else: its stat answers those, absent for any other rel, and records
    /// the rel; a `PUT` panics (where it is used, none may go out).
    struct Holding {
        held: Vec<(String, u64, String)>,
        stats: Mutex<Vec<String>>,
    }

    impl Holding {
        fn new(held: Vec<(String, u64, String)>) -> Holding {
            Holding { held, stats: Mutex::new(Vec::new()) }
        }
    }

    impl DataPlane for Holding {
        async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SeedState>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, _: &SeedQuery, _: &Path, _: u64) -> Result<DpReply<SeedReply>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, rel: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
            self.stats.lock().unwrap().push(rel.to_string());
            let stat = match self.held.iter().find(|(r, ..)| r == rel) {
                Some((_, size, sha)) => TranscriptStat { present: true, size: *size, sha256: Some(sha.clone()), mtime: None },
                None => TranscriptStat { present: false, size: 0, sha256: None, mtime: None },
            };
            Ok(DpReply::ok(200, stat))
        }

        async fn put_transcript(&self, _: &AgentTarget, _: &AuthToken, rel: &str, _: &Path, _: u64) -> Result<DpReply<TranscriptReply>, BridgeError> {
            panic!("PUT /transcript of {rel}: none may go out here");
        }

        async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }
    }

    /// CUSTODY-2: a hit in a subagent's file alone, on a VM that holds
    /// neither file, refuses the whole upload before its first `PUT`: both
    /// files stat'ed first (this data plane answers absent, and its `PUT`
    /// panics: the clean transcript's would have gone out first), then exit
    /// 9 naming `transcript:REL`, the line and the rule, never the value;
    /// the clean transcript's copy gone with the refusal; `seed_refused`
    /// audited with the VM, no `transcript_put`. P1's scan of the same copy
    /// refuses the same way, before any VM (its row names none).
    #[tokio::test]
    async fn a_tripwire_in_a_subagent_file_the_vm_lacks_refuses_the_upload_before_any_put() {
        let w = World::new();
        w.plant(&format!("{ID}.jsonl"), &lines("nothing to see"));
        w.plant(&format!("{ID}/subagents/agent-a1.jsonl"), &lines(&format!("aws_access_key_id = {}", key())));
        let (api, target, caps, dp) = (FakeMicrovmApi::new(), target(), vec![CAP_WORKSPACE_V1.to_string()], Holding::new(Vec::new()));
        let ctx = EnsureCtx { api: &api, dp: &dp, tokens: &Tokens, paths: &w.paths, cfg: &w.cfg, target: &target, caps: &caps, ws: &w.ws, lim: SeedLimits::wrapper(&w.cfg), deadline: None, progress: &|_: SeedProgress| {} };
        let want = format!("transcript:{ID}/subagents/agent-a1.jsonl line 2: rule aws-access-key-id");
        let e = ensure(&ctx, &w.projects, &["-mac"], ID, "-vm").await.unwrap_err();
        assert_eq!(finding(e), want);
        assert_eq!(*dp.stats.lock().unwrap(), [format!("-vm/{ID}.jsonl"), format!("-vm/{ID}/subagents/agent-a1.jsonl")], "both stat'ed first");
        assert!(w.tmp_left().is_empty(), "the copies went with the refusal: {:?}", w.tmp_left());
        let rows = w.rows("seed_refused");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!((rows[0]["detail"]["step"].as_str(), rows[0]["detail"]["code"].as_str(), rows[0]["detail"]["vm"].as_str()), (Some("transcript"), Some("finding"), Some("microvm-1")));
        assert!(w.rows("transcript_put").is_empty(), "nothing went up");
        assert_eq!(finding(scan_mac_copy(&w.paths, &w.cfg, &w.ws, &w.projects, &["-mac"], ID, "-vm").unwrap_err()), want);
        let rows = w.rows("seed_refused");
        assert_eq!((rows.len(), rows[1]["detail"].get("vm")), (2, None), "P1's: no VM chosen yet");
        assert!(!std::fs::read_to_string(w.paths.audit()).unwrap().contains(&key()), "no value in the audit");
    }

    /// P1's scan reads what the upload would send and nothing else: a clean
    /// copy passes, and so do a hit in a file no transcript rel names (it is
    /// never sent) and a session the Mac holds no copy of; a hit in the
    /// transcript's second line refuses, and so does a subagent file whose
    /// name trips a rule (the name shown as `a path name`). Both audited
    /// `seed_refused` with no VM; nothing written to `state/tmp/`.
    #[test]
    fn p1s_scan_refuses_only_what_the_upload_would_send() {
        let w = World::new();
        let scan = |id: &str| scan_mac_copy(&w.paths, &w.cfg, &w.ws, &w.projects, &["-mac"], id, "-vm");
        let main = w.plant(&format!("{ID}.jsonl"), &lines("nothing to see"));
        // Directly below the session: no transcript rel names it, so it never goes up.
        w.plant(&format!("{ID}/stray.jsonl"), &lines(&format!("aws_access_key_id = {}", key())));
        scan(ID).unwrap();
        scan("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c").unwrap();
        std::fs::write(&main, lines(&format!("aws_access_key_id = {}", key()))).unwrap();
        assert_eq!(finding(scan(ID).unwrap_err()), format!("transcript:{ID}.jsonl line 2: rule aws-access-key-id"));
        std::fs::write(&main, lines("nothing to see")).unwrap();
        w.plant(&format!("{ID}/subagents/agent-{}.jsonl", key()), &lines("nothing to see"));
        assert_eq!(finding(scan(ID).unwrap_err()), "transcript:a path name: rule aws-access-key-id");
        let rows = w.rows("seed_refused");
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|r| r["detail"]["step"] == "transcript" && r["detail"].get("vm").is_none()), "{rows:?}");
        assert!(!w.paths.tmp().exists(), "P1 copies nothing");
    }

    /// The data plane of [`the_put_sends_exactly_the_bytes_the_scan_read`]:
    /// its stat rewrites the Mac's file (the same length, an access key id in
    /// it), as a local claude writing on would, and answers absent; its put
    /// keeps the bytes it was given and answers them written.
    struct Rewriting {
        mac: PathBuf,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl DataPlane for Rewriting {
        async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SeedState>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, _: &SeedQuery, _: &Path, _: u64) -> Result<DpReply<SeedReply>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
            let len = std::fs::metadata(&self.mac).unwrap().len() as usize;
            let planted = format!("{{\"k\":\"{}\"}}", key());
            std::fs::write(&self.mac, format!("{planted:<width$}\n", width = len - 1)).unwrap();
            Ok(DpReply::ok(200, TranscriptStat { present: false, size: 0, sha256: None, mtime: None }))
        }

        async fn put_transcript(&self, _: &AgentTarget, _: &AuthToken, _: &str, body: &Path, len: u64) -> Result<DpReply<TranscriptReply>, BridgeError> {
            use sha2::{Digest, Sha256};
            let mut bytes = std::fs::read(body).unwrap();
            bytes.truncate(len as usize);
            let sha256 = hex::encode(Sha256::digest(&bytes));
            self.sent.lock().unwrap().push(bytes);
            Ok(DpReply::ok(201, TranscriptReply { outcome: TranscriptWrite::Written, size: len, sha256 }))
        }

        async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }
    }

    /// Tokens that are always there.
    struct Tokens;

    impl TokenSource for Tokens {
        async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
            Ok(AuthToken { headers: std::collections::BTreeMap::new(), port, expires_at_unix: u64::MAX })
        }
    }

    /// What the `PUT` sends is exactly what the scan read: the Mac's file is
    /// rewritten after the scan, before the stat's answer (the same length,
    /// an access key id in it); the upload sends the scanned bytes, its
    /// copy, the VM's answer matches them, and the copy is gone after.
    #[tokio::test]
    async fn the_put_sends_exactly_the_bytes_the_scan_read() {
        let w = World::new();
        let text = lines("nothing to see");
        let mac = w.plant(&format!("{ID}.jsonl"), &text);
        let dp = Rewriting { mac: mac.clone(), sent: Mutex::new(Vec::new()) };
        let (api, target, caps) = (FakeMicrovmApi::new(), target(), vec![CAP_WORKSPACE_V1.to_string()]);
        let ctx = EnsureCtx { api: &api, dp: &dp, tokens: &Tokens, paths: &w.paths, cfg: &w.cfg, target: &target, caps: &caps, ws: &w.ws, lim: SeedLimits::wrapper(&w.cfg), deadline: None, progress: &|_: SeedProgress| {} };
        let up = ensure(&ctx, &w.projects, &["-mac"], ID, "-vm").await.unwrap();
        assert_eq!(up, TranscriptOutcome::Uploaded { files: 1, bytes: text.len() as u64 });
        assert_eq!(*dp.sent.lock().unwrap(), [text.into_bytes()], "the bytes the scan read, not the file's now");
        assert!(std::fs::read_to_string(&mac).unwrap().contains(&key()), "the Mac's file changed meanwhile");
        assert!(w.tmp_left().is_empty(), "the copy went with the upload: {:?}", w.tmp_left());
    }

    /// Review F2-R1: a chat reopened on the VM it ran on holds what that
    /// VM's tools printed, mirrored to the Mac. A file with a hit that the
    /// VM holds the same (its size and sha256) is never sent, so never
    /// refused (`AlreadyThere`), and neither is one it holds longer
    /// (`VmLonger`); held shorter, or other bytes at its length, it would be
    /// sent, so the hit refuses it before any `PUT` (this data plane's
    /// panics). Only the refusals are audited `seed_refused`.
    #[tokio::test]
    async fn a_hit_in_a_file_the_vm_holds_already_is_never_sent_so_never_refused() {
        use sha2::{Digest, Sha256};
        let w = World::new();
        let text = lines(&format!("aws_access_key_id = {}", key()));
        w.plant(&format!("{ID}.jsonl"), &text);
        let (len, sha, other) = (text.len() as u64, hex::encode(Sha256::digest(text.as_bytes())), hex::encode(Sha256::digest(b"other bytes")));
        let (api, target, caps) = (FakeMicrovmApi::new(), target(), vec![CAP_WORKSPACE_V1.to_string()]);
        let want = format!("transcript:{ID}.jsonl line 2: rule aws-access-key-id");
        let cases = [
            ((len, sha), Some(TranscriptOutcome::AlreadyThere)),
            ((len + 7, other.clone()), Some(TranscriptOutcome::VmLonger { vm: len + 7, mac: len })),
            ((len - 7, other.clone()), None),
            ((len, other), None),
        ];
        for ((size, held), outcome) in cases {
            let dp = Holding::new(vec![(format!("-vm/{ID}.jsonl"), size, held)]);
            let ctx = EnsureCtx { api: &api, dp: &dp, tokens: &Tokens, paths: &w.paths, cfg: &w.cfg, target: &target, caps: &caps, ws: &w.ws, lim: SeedLimits::wrapper(&w.cfg), deadline: None, progress: &|_: SeedProgress| {} };
            let got = ensure(&ctx, &w.projects, &["-mac"], ID, "-vm").await;
            match outcome {
                Some(outcome) => assert_eq!(got.unwrap(), outcome, "held {size} bytes"),
                None => assert_eq!(finding(got.unwrap_err()), want, "held {size} bytes"),
            }
        }
        let puts: Vec<String> = w.rows("transcript_put").iter().map(|r| r["detail"]["outcome"].as_str().unwrap_or_default().to_string()).collect();
        assert_eq!(puts, ["already_there", "vm_longer"]);
        let rows = w.rows("seed_refused");
        assert!(rows.len() == 2 && rows.iter().all(|r| r["detail"]["step"] == "transcript" && r["detail"]["vm"] == "microvm-1"), "{rows:?}");
        assert!(w.tmp_left().is_empty(), "{:?}", w.tmp_left());
    }
}
