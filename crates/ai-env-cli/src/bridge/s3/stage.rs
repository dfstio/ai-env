//! `ai-env session stage UUID [--warm]` (S9 plan §5, G4): a chat that
//! began on this Mac goes up to S3 before it reopens remote: stream-scanned
//! (the tripwires: a finding refuses before any request), then a multipart
//! upload to `v1/<sid>/mac/<sha256>` (`MULTIPART_PART` parts,
//! `MULTIPART_PARALLEL` at once, each with its signed sha256), resumable
//! through `state/transcripts/<sid>/stage.toml` ([`Stage`], deleted once
//! complete); then the manifest (`origin = "mac"`), the original moved to
//! `Paths::transcript_origin`, and the view in its place. Phase 0 declares
//! the stage file's serde types and [`cmd_stage`]'s stub. With `--warm`
//! (S9, R5-AWS-1) the chat's workspace is warmed (`vm warm`) and the chat
//! restored from S3 into that VM ([`restore_into`], no deadline): the way a
//! chat over what a reopen pulls inline (`wire::s3::INLINE_MAX`) reopens,
//! one begun on a VM (S3 holds it already: nothing to stage) as well.
use super::client::{Body, S3Client, Written};
use super::manifest::{self, Manifest, ManifestFile, ManifestPart};
use super::{S3Sign, S3Target};
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::errors::BridgeError;
use crate::bridge::scan::Rules;
use crate::bridge::view::{ViewOutcome, ViewTarget};
use crate::bridge::workspace::transcript::FileDigest;
use crate::errors::CliError;
use crate::store::Keystore;
use crate::wire::s3::{S3Key, MULTIPART_PARALLEL, MULTIPART_PART};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The stage file's version.
pub const STAGE_V: u32 = 1;

/// `stage.toml`: a multipart upload under way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    /// [`STAGE_V`].
    pub v: u32,
    pub session: String,
    /// `v1/<sid>/mac/<sha256>`.
    pub key: String,
    pub upload_id: String,
    pub len: u64,
    pub sha256: String,
    pub part_len: u64,
    /// When the upload began (RFC 3339 UTC).
    pub started: String,
    /// The parts uploaded so far.
    #[serde(default)]
    pub parts: Vec<StagePart>,
}

/// One uploaded part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagePart {
    pub number: u32,
    pub len: u64,
    pub sha256: String,
    pub etag: String,
}

// ---- the stage (G4) ---------------------------------------------------------------------------

/// The largest chat `session stage` takes: what one PUT from the VM can
/// restore (a pull's parts are summed to at most `PULL_MAX`).
pub const STAGE_MAX: u64 = crate::wire::workspace::PULL_MAX;

/// A chat of this Mac as the stage finds it: its project directory, the
/// directory's name (the session's slug on the Mac and in the VM), and its
/// files below that directory (`<sid>.jsonl` first, then the `<sid>/`
/// subtree's regular files, as the S2 seeder walks them) with their sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacChat {
    pub dir: PathBuf,
    pub slug: String,
    pub files: Vec<(String, u64)>,
}

impl MacChat {
    /// Every file's bytes, summed.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|(_, n)| *n).sum()
    }

    /// `<dir>/<sid>.jsonl`.
    #[must_use]
    pub fn main_path(&self, sid: &str) -> PathBuf {
        self.dir.join(format!("{sid}.jsonl"))
    }
}

/// `sid`'s chat under `projects`: the first of `seed::candidates` (`slugs`
/// first, then every project directory) holding `<sid>.jsonl`, its files
/// listed by the seeder's rules up to `cap` bytes in all (more:
/// `TranscriptTooLarge`, exit 9). `Ok(None)`: no such chat on this Mac.
pub fn locate(projects: &Path, slugs: &[&str], sid: &str, cap: u64) -> Result<Option<MacChat>, BridgeError> {
    let Some(dir) = crate::bridge::seed::candidates(projects, slugs, sid).into_iter().next() else { return Ok(None) };
    let slug = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let files = crate::bridge::seed::transcript_files_capped(&dir, sid, cap)?;
    let main = format!("{sid}.jsonl");
    if files.first().is_none_or(|(rel, _)| *rel != main) {
        return Ok(None);
    }
    Ok(Some(MacChat { dir, slug, files }))
}

/// `rel` as a finding names it: `a path name` when the name itself trips a rule.
fn shown(rules: &Rules, rel: &str) -> String {
    if rules.scan_bytes(rel.as_bytes()).is_empty() {
        rel.to_string()
    } else {
        crate::bridge::workspace::blobscan::PATH_NAME.to_string()
    }
}

/// Every file of `chat` read once through the tripwires and digested
/// (`workspace::transcript::digest_file`: the sha256, the fingerprint, the
/// sha256 of each `part_len` part), each name through the tripwires too. Any
/// finding refuses before any request: `WorkspaceRefused { finding }` (exit
/// 9) naming `transcript:REL line N: rule R`, never a value. The digests, in
/// `chat.files`' order.
pub fn scan_chat(rules: &Rules, chat: &MacChat, part_len: u64) -> Result<Vec<FileDigest>, BridgeError> {
    use crate::bridge::workspace::blobscan::{finding_lines, Finding};
    let mut findings: Vec<Finding> = Vec::new();
    let mut digests = Vec::with_capacity(chat.files.len());
    for (rel, len) in &chat.files {
        let location = format!("transcript:{}", shown(rules, rel));
        let finding = |(line, rule): (usize, String)| Finding { location: location.clone(), object: None, line, rule, key: None };
        findings.extend(rules.scan_bytes(rel.as_bytes()).into_iter().map(|(_, rule)| finding((0, rule))));
        let d = crate::bridge::workspace::transcript::digest_file(rules, &chat.dir.join(rel), *len, part_len)?;
        findings.extend(d.hits.iter().cloned().map(finding));
        digests.push(d);
    }
    if !findings.is_empty() {
        return Err(BridgeError::WorkspaceRefused { code: crate::bridge::workspace::code::FINDING, message: finding_lines(&findings) });
    }
    Ok(digests)
}

/// The stage file of `sid`, `Ok(None)` when none.
pub fn read_stage(paths: &Paths, sid: &str) -> Result<Option<Stage>, BridgeError> {
    let path = paths.transcript_stage(sid);
    let Some(text) = crate::bridge::registry::read_regular_file(&path)? else { return Ok(None) };
    let s: Stage = toml::from_str(&text).map_err(|e| BridgeError::Config(format!("{}: {}", path.display(), e.message())))?;
    Ok(Some(s).filter(|s| s.v == STAGE_V && s.session == sid))
}

/// Write `s` atomically, 0600, `state/transcripts/<sid>/` a real 0700 directory.
fn write_stage(paths: &Paths, s: &Stage) -> Result<(), BridgeError> {
    crate::bridge::registry::ensure_private_dir(&paths.transcript_dir(&s.session))?;
    let text = toml::to_string(s).map_err(|e| BridgeError::Config(format!("stage of {}: {e}", s.session)))?;
    crate::bridge::infra::write_atomic_mode(&paths.transcript_stage(&s.session), text.as_bytes(), 0o600)
}

/// What one file's upload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    /// The version S3 named (empty: unknown, the key held its bytes already).
    pub version_id: String,
    pub parts: u32,
    /// A multipart upload went on from `stage.toml` (its parts S3 held were not sent again).
    pub resumed: bool,
    /// The key held an object already (412): named by its bytes' sha256, so those bytes.
    pub existed: bool,
}

/// Upload `path` (its digest `d`) as `key` through `client`: one part is a
/// PutObject; more are a multipart upload of `part_len` parts, at most
/// `MULTIPART_PARALLEL` at once, each streamed from the file with its signed
/// sha256, its budget allowing for the parts in flight beside it
/// (`client::budget`), resumable through `stage.toml` (the parts S3 lists
/// with the expected size and checksum are not sent again; an upload S3 no
/// longer knows starts over), completed new-only, `stage.toml` removed
/// after. A part, or the PutObject, that gets no answer (or S3's 500 or
/// 503) goes again, `client::PART_TRIES` tries in all.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str, key: &str, path: &Path, d: &FileDigest, part_len: u64) -> Result<Uploaded, BridgeError> {
    use futures_util::StreamExt as _;
    let part_len = part_len.max(1);
    if d.parts.len() <= 1 {
        let w = client.put_object(key, Body::File { path: path.to_path_buf(), offset: 0, len: d.len }, d.len, &d.sha256).await?;
        return Ok(match w {
            Written::Stored(v) => Uploaded { version_id: v, parts: 1, resumed: false, existed: false },
            Written::Exists => Uploaded { version_id: String::new(), parts: 1, resumed: false, existed: true },
        });
    }
    let prior = read_stage(paths, sid)?;
    let same = |s: &Stage| s.key == key && s.len == d.len && s.sha256 == d.sha256 && s.part_len == part_len;
    let mut resumed = prior.as_ref().is_some_and(same);
    let mut stage = match prior {
        Some(s) if same(&s) => s,
        other => {
            if let Some(old) = other {
                // Another upload of this session (other bytes): S3's lifecycle aborts it after a day anyway.
                let _ = client.abort_multipart(&old.key, &old.upload_id).await;
            }
            let upload_id = client.create_multipart(key).await?;
            let s = Stage { v: STAGE_V, session: sid.to_string(), key: key.to_string(), upload_id, len: d.len, sha256: d.sha256.clone(), part_len, started: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), parts: Vec::new() };
            write_stage(paths, &s)?;
            s
        }
    };
    if resumed {
        match client.list_parts(key, &stage.upload_id).await? {
            None => {
                resumed = false;
                stage.upload_id = client.create_multipart(key).await?;
                stage.parts.clear();
            }
            Some(listed) => {
                let expected = |n: u32| d.parts.get(n as usize - 1).cloned();
                stage.parts = listed
                    .into_iter()
                    .filter_map(|p| {
                        let sha = expected(p.number)?;
                        let want = part_len.min(d.len - u64::from(p.number - 1) * part_len);
                        let checksum_ok = p.checksum.as_deref().is_none_or(|c| crate::wire::s3::sha256_b64(&sha).as_deref() == Some(c));
                        (p.size == want && checksum_ok).then_some(StagePart { number: p.number, len: p.size, sha256: sha, etag: p.etag })
                    })
                    .collect();
            }
        }
        write_stage(paths, &stage)?;
    }
    let count = u32::try_from(d.parts.len()).map_err(|_| BridgeError::Config(format!("{key}: more than {} parts", u32::MAX)))?;
    let done: std::collections::BTreeSet<u32> = stage.parts.iter().map(|p| p.number).collect();
    let upload_id = stage.upload_id.clone();
    let missing: Vec<u32> = (1..=count).filter(|n| !done.contains(n)).collect();
    // The parts in flight share the uplink: each one's budget allows for all of them (`client::budget`).
    let shared = MULTIPART_PARALLEL.min(missing.len());
    let sends = missing.into_iter().map(|n| {
        let (upload_id, sha) = (upload_id.clone(), d.parts[n as usize - 1].clone());
        let offset = u64::from(n - 1) * part_len;
        let len = part_len.min(d.len - offset);
        async move {
            let etag = client.upload_part(key, &upload_id, n, Body::File { path: path.to_path_buf(), offset, len }, len, &sha, shared).await?;
            Ok::<StagePart, BridgeError>(StagePart { number: n, len, sha256: sha, etag })
        }
    });
    let mut running = futures_util::stream::iter(sends).buffer_unordered(MULTIPART_PARALLEL);
    while let Some(part) = running.next().await {
        stage.parts.push(part?);
        stage.parts.sort_by_key(|p| p.number);
        write_stage(paths, &stage)?;
    }
    drop(running);
    let list: Vec<(u32, String, String)> = stage.parts.iter().map(|p| (p.number, p.etag.clone(), p.sha256.clone())).collect();
    let w = client.complete_multipart(key, &upload_id, &list).await?;
    crate::bridge::registry::remove_if_present(&paths.transcript_stage(sid))?;
    Ok(match w {
        Written::Stored(v) => Uploaded { version_id: v, parts: count, resumed, existed: false },
        Written::Exists => Uploaded { version_id: String::new(), parts: count, resumed, existed: true },
    })
}

/// What a chat's upload left: the manifest to write (`origin = "mac"`), and
/// for the report the main object's key, the bytes, the parts, whether it
/// resumed, whether S3 held it already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatUpload {
    pub manifest: Manifest,
    pub key: String,
    pub bytes: u64,
    pub parts: u32,
    pub resumed: bool,
    pub existed: bool,
}

/// Upload every file of `chat` (`digests` in its order) as
/// `v1/<sid>/mac/<sha256>` objects (the main transcript as [`upload_file`]
/// does; each subtree file likewise, by its own bytes' sha256), and build
/// the manifest: one part (the main object), gen 0, its files by rel under
/// the chat's slug. `state/transcripts/<sid>/` is made before the first
/// request, so an upload cut before its manifest leaves a trace that
/// `forget --purge` and `gc --remote` find. One ListObjectsV2 of
/// `v1/<sid>/mac/` first: an object S3 holds already at its key with its
/// length (the key is its bytes' sha256, and only this Mac writes there) is
/// not sent again, its version unknown, as after a 412.
pub async fn upload_chat<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str, chat: &MacChat, digests: &[FileDigest], part_len: u64, at: &str) -> Result<ChatUpload, BridgeError> {
    let (Some((main_rel, _)), Some(main)) = (chat.files.first(), digests.first()) else {
        return Err(BridgeError::Config(format!("{sid}: no transcript to stage")));
    };
    if main.len == 0 {
        return Err(BridgeError::Config(format!("{}: the transcript is empty: nothing to stage", chat.dir.join(main_rel).display())));
    }
    crate::bridge::registry::ensure_private_dir(&paths.transcript_dir(sid))?;
    let held: Vec<super::client::Listed> = client.list(&format!("{}{sid}/mac/", crate::wire::s3::KEY_PREFIX)).await?;
    let upload = |key: String, path: PathBuf, d: FileDigest| {
        let there = held.iter().any(|o| o.key == key && o.size == d.len);
        async move {
            if there {
                tracing::info!(session = sid, "{key}: S3 holds it already: not sent again");
                return Ok(Uploaded { version_id: String::new(), parts: u32::try_from(d.parts.len().max(1)).unwrap_or(u32::MAX), resumed: false, existed: true });
            }
            upload_file(client, paths, sid, &key, &path, &d, part_len).await
        }
    };
    let key = S3Key::Mac { session: sid.to_string(), sha256: main.sha256.clone() }.render();
    let up = upload(key.clone(), chat.dir.join(main_rel), main.clone()).await?;
    let mut m = Manifest::new(sid, client.target(), manifest::ORIGIN_MAC, &format!("{}/{sid}.jsonl", chat.slug), at);
    m.parts.push(ManifestPart { key: key.clone(), version_id: up.version_id.clone(), from: 0, len: main.len, sha256: main.sha256.clone() });
    m.committed = main.len;
    m.fp = main.fp.clone();
    for ((rel, _), d) in chat.files.iter().zip(digests).skip(1) {
        if d.len == 0 {
            continue;
        }
        let fkey = S3Key::Mac { session: sid.to_string(), sha256: d.sha256.clone() }.render();
        // The part length the digests were computed with: a file over it goes up in those very parts, each with its sha256.
        let f = upload(fkey.clone(), chat.dir.join(rel), d.clone()).await?;
        let version = Some(f.version_id).filter(|v| !v.is_empty()).or_else(|| m.file_version(&fkey));
        m.files.push(ManifestFile { rel: format!("{}/{rel}", chat.slug), key: fkey, version_id: version, len: d.len, sha256: d.sha256.clone() });
    }
    Ok(ChatUpload { manifest: m, key, bytes: chat.bytes(), parts: up.parts, resumed: up.resumed, existed: up.existed })
}

/// Move `chat`'s files (`<sid>.jsonl`, the `<sid>/` subtree) into
/// `state/transcripts/<sid>/origin/` (0700), never through a symlink: a
/// rename, else (another volume) a streamed copy ([`copy_across`]), then the
/// original removed. A copy already there from an earlier move is replaced.
/// The directory they went to.
pub fn move_to_origin(paths: &Paths, sid: &str, chat: &MacChat) -> Result<PathBuf, BridgeError> {
    let dest = paths.transcript_origin(sid);
    crate::bridge::registry::ensure_private_dir(&dest)?;
    let io = |what: &str, p: &Path, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", p.display())));
    let subtree = chat.dir.join(sid);
    let dest_subtree = dest.join(sid);
    if std::fs::symlink_metadata(&dest_subtree).is_ok_and(|m| m.is_dir()) {
        std::fs::remove_dir_all(&dest_subtree).map_err(|e| io("remove", &dest_subtree, e))?;
    }
    for (rel, _) in &chat.files {
        let (from, to) = (chat.dir.join(rel), dest.join(rel));
        if let Some(parent) = to.parent() {
            crate::bridge::registry::ensure_private_dir(parent)?;
        }
        match std::fs::rename(&from, &to) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                copy_across(&from, &to)?;
                std::fs::remove_file(&from).map_err(|e| io("remove", &from, e))?;
            }
            Err(e) => return Err(io("move", &from, e)),
        }
    }
    // What the seeder skipped (symlinks, other files) stays with the subtree's directory, which goes once empty.
    if std::fs::symlink_metadata(&subtree).is_ok_and(|m| m.is_dir()) {
        remove_empty_dirs(&subtree);
    }
    Ok(dest)
}

/// `from` (a regular file, opened without following a symlink, never
/// blocking) copied to `to` across volumes in bounded memory: streamed into a
/// `create_new` 0600 temp file beside `to`, fsync'ed, then renamed onto `to`
/// (never a symlink). The temp file goes on any error; `from` stays.
pub fn copy_across(from: &Path, to: &Path) -> Result<(), BridgeError> {
    use std::os::unix::fs::PermissionsExt as _;
    let io = |what: &str, p: &Path, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", p.display())));
    let mut src = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(from).map_err(|e| io("open", from, e))?;
    if !src.metadata().map_err(|e| io("stat", from, e))?.is_file() {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is not a regular file", from.display()))));
    }
    let dir = to.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".ai-env-{}.tmp", uuid::Uuid::now_v7().simple()));
    let result = (|| {
        let mut dst = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp).map_err(|e| io("create", &tmp, e))?;
        dst.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| io("chmod", &tmp, e))?;
        std::io::copy(&mut src, &mut dst).map_err(|e| io("copy into", &tmp, e))?;
        dst.sync_all().map_err(|e| io("fsync", &tmp, e))?;
        drop(dst);
        if std::fs::symlink_metadata(to).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(BridgeError::Config(format!("{} is a symlink; refusing to replace it", to.display())));
        }
        std::fs::rename(&tmp, to).map_err(|e| io("rename onto", to, e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The sha256 (lowercase hex) of `path` (a regular file, opened without
/// following a symlink, never blocking), streamed, when it is exactly `len`
/// bytes long; `Ok(None)` when it is another length (nothing is read then).
pub fn sha256_if_len(path: &Path, len: u64) -> Result<Option<String>, BridgeError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let at = |what: &str, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", path.display())));
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|e| at("open", e))?;
    let md = file.metadata().map_err(|e| at("stat", e))?;
    if !md.is_file() || md.len() != len {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    let (mut reader, mut buf, mut read) = (file.take(len), vec![0u8; 1 << 20], 0u64);
    loop {
        let n = reader.read(&mut buf).map_err(|e| at("read", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        read += n as u64;
    }
    Ok((read == len).then(|| hex::encode(hasher.finalize())))
}

/// Remove `dir` and the directories below it that are empty (bottom up); anything else stays.
fn remove_empty_dirs(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                remove_empty_dirs(&e.path());
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// The last `wire::view::VIEW_TAIL_MAX` bytes of `path` (what a view is built from).
pub fn tail_of(path: &Path) -> Result<Vec<u8>, BridgeError> {
    use std::io::{Read as _, Seek as _};
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display()))))?;
    let len = f.metadata()?.len();
    let from = len.saturating_sub(crate::wire::view::VIEW_TAIL_MAX);
    f.seek(std::io::SeekFrom::Start(from))?;
    let mut tail = Vec::new();
    f.take(crate::wire::view::VIEW_TAIL_MAX).read_to_end(&mut tail)?;
    Ok(tail)
}

/// A view builder (`wire::view::build_view`; tests pass their own).
pub type ViewBuilder<'a> = &'a dyn Fn(&[u8], u32) -> Result<crate::wire::view::TranscriptViewReply, String>;

/// Once a chat's objects and manifest are in place: its view built here
/// from its own last bytes (`build`), the originals moved to `origin/`, then
/// the view written in their place (`bridge::view`, the session's tripwires
/// masking it, audited `transcript_view`). A view that cannot be built
/// leaves the originals where they are (a warning; the chat is in S3
/// already, and a reopen restores it from there). The view's rel and where
/// the originals went.
#[allow(clippy::too_many_arguments)]
pub fn leave_view(paths: &Paths, sid: &str, chat: &MacChat, projects: &Path, mac_cwd: &str, n: u32, rules: &Rules, build: ViewBuilder<'_>) -> Result<(Option<String>, Option<PathBuf>), BridgeError> {
    let reply = match tail_of(&chat.main_path(sid)).and_then(|tail| build(&tail, n).map_err(BridgeError::Config)) {
        Ok(r) => r,
        Err(e) => {
            crate::bridge::voice::warn(&format!("the view of {sid} could not be built ({e}): its transcript stays where it is on this Mac (it is in S3 already)"));
            return Ok((None, None));
        }
    };
    let origin = move_to_origin(paths, sid, chat)?;
    let target = ViewTarget { mac_projects: projects, slug: &chat.slug, session_id: sid, mac_cwd };
    let outcome = crate::bridge::view::write_view(&target, &reply, n, rules)?;
    super::sync::audit_view(paths, sid, "-", &outcome);
    Ok((matches!(outcome, ViewOutcome::Written { .. } | ViewOutcome::Unchanged { .. }).then(|| target.rel()), Some(origin)))
}

/// [`leave_view`] for a chat whose copy here is S8's mirror (`origin_of`'s
/// `s8_mirror`: a chat begun on a VM), once its objects and manifest
/// (`origin = "vm"`) are in place: `session migrate-s9`'s gone-VM form. Its
/// view is built here from the mirror's own last bytes (`build`), the
/// mirror's files are deleted (a remote chat's full transcript never stays
/// on this Mac, not even under `origin/`, which holds only a Mac-begun
/// chat's original or a mirror skipped for a finding), then the view is
/// written in their place (audited `transcript_view` for `vm`). A view that
/// cannot be built leaves the mirror where it is (a warning; the chat is in
/// S3 already). The view's rel.
#[allow(clippy::too_many_arguments)]
pub fn replace_mirror(paths: &Paths, sid: &str, chat: &MacChat, projects: &Path, mac_cwd: &str, n: u32, rules: &Rules, build: ViewBuilder<'_>, vm: &str) -> Result<Option<String>, BridgeError> {
    let reply = match tail_of(&chat.main_path(sid)).and_then(|tail| build(&tail, n).map_err(BridgeError::Config)) {
        Ok(r) => r,
        Err(e) => {
            crate::bridge::voice::warn(&format!("the view of {sid} could not be built ({e}): its S8 mirror stays where it is on this Mac (the chat is in S3 already)"));
            return Ok(None);
        }
    };
    super::commands::delete_mirror(chat, sid)?;
    let target = ViewTarget { mac_projects: projects, slug: &chat.slug, session_id: sid, mac_cwd };
    let outcome = crate::bridge::view::write_view(&target, &reply, n, rules)?;
    super::sync::audit_view(paths, sid, vm, &outcome);
    Ok(matches!(outcome, ViewOutcome::Written { .. } | ViewOutcome::Unchanged { .. }).then(|| target.rel()))
}

/// What `session stage` did (`--json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageReport {
    pub session: String,
    pub bytes: u64,
    pub parts: u32,
    pub key: String,
    /// `staged`, `resumed` or `already`.
    pub outcome: &'static str,
    /// The view's rel under the projects directory.
    pub view: Option<String>,
    /// Where the originals went.
    pub origin: Option<PathBuf>,
}

/// The stage of `sid` (`cmd_stage` without the printing): refusals first,
/// before any request or Touch ID — not a uuid; a chat that did not begin on
/// this Mac (`manifest::origin_of`: a VM's, or an S8 mirror's, which
/// `session migrate-s9` takes); no such chat; a view with no manifest behind
/// it; a chat that could never reopen once its original is a view
/// ([`chat_workspace`]: the cwd its transcript records outside the roots or
/// in no git repository, exit 9; none recorded, or gone, exit 1); a finding
/// (exit 9) — then `signer` (the runtime key: one unseal, asked only now
/// through `unseal`) presigns the upload, then the manifest, then the view
/// in the original's place, its lines' cwd the row's, else the one the
/// transcript recorded. A manifest of this Mac's chat is `already` (its
/// view written if the original is still in place and is the copy S3
/// holds; another copy there is refused, exit 1, and left alone: the chat
/// went on here after a cut stage).
#[allow(clippy::too_many_arguments)]
pub async fn stage<S: S3Sign, F, Fut>(paths: &Paths, cfg: &BridgeConfig, target: &S3Target, projects: &Path, sid: &str, part_len: u64, build: ViewBuilder<'_>, unseal: F) -> Result<StageReport, BridgeError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<S, BridgeError>>,
{
    let t0 = std::time::Instant::now();
    refuse_other_origin(paths, sid)?;
    let row = crate::bridge::registry::read(paths, sid).ok().flatten();
    let slugs: Vec<&str> = row.as_ref().and_then(|r| r.slug.as_deref()).into_iter().collect();
    cfg.transcript.validate()?;
    let n = cfg.transcript.view_messages;
    let rules = std::sync::Arc::new(crate::bridge::scan::load_lists(Some((paths, &cfg.review)), None, None, false).map_err(BridgeError::Config)?.0);
    let found = locate(projects, &slugs, sid, STAGE_MAX)?;
    let is_view = found.as_ref().is_some_and(|c| crate::bridge::view::is_view_file(&c.main_path(sid)));
    // Where the chat reopens, before anything is sent or moved: a view of a chat that could never reopen remote
    // would leave its original out of reach (the local resume of a view is refused).
    let workspace = match &found {
        Some(_) if !is_view => Some(chat_workspace(paths, cfg, projects, sid)?),
        _ => None,
    };
    // The view's lines carry the row's cwd, else the one the transcript recorded (what Cursor used): never "".
    let mac_cwd = row.as_ref().and_then(|r| r.cwd.clone()).or_else(|| workspace.as_ref().map(|w| w.recorded.clone())).unwrap_or_default();
    if let Some(m) = manifest::read(paths, sid)? {
        // Staged already: the manifest holds it; an original still in place (a stage cut before its view) gets the
        // view now, when it is the copy S3 holds.
        let (view, origin) = match &found {
            Some(chat) if !is_view => {
                staged_copy(&m, chat, sid)?;
                leave_view(paths, sid, chat, projects, &mac_cwd, n, &rules, build)?
            }
            _ => (row.as_ref().and_then(|r| r.view.clone()), Some(paths.transcript_origin(sid)).filter(|p| p.exists())),
        };
        let report = StageReport { session: sid.to_string(), bytes: m.committed + m.files.iter().map(|f| f.len).sum::<u64>(), parts: 1, key: m.parts.first().map(|p| p.key.clone()).unwrap_or_default(), outcome: "already", view, origin };
        audit_stage(paths, &report, t0);
        return Ok(report);
    }
    let Some(chat) = found else {
        return Err(BridgeError::Config(format!("no chat {sid} on this Mac (no {sid}.jsonl under {})", projects.display())));
    };
    if is_view {
        return Err(BridgeError::Config(format!("{} is a view and no manifest stands behind it: its transcript is not on this Mac", chat.main_path(sid).display())));
    }
    let digests = {
        let (rules, chat) = (std::sync::Arc::clone(&rules), chat.clone());
        crate::bridge::workspace::blocking(move || scan_chat(&rules, &chat, part_len)).await??
    };
    let signer = unseal().await?;
    let client = S3Client::new(&signer, target)?;
    let at = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
    let up = upload_chat(&client, paths, sid, &chat, &digests, part_len, &at).await?;
    {
        let _held = manifest::lock(paths, sid).await?;
        manifest::write(paths, &up.manifest)?;
    }
    let (view, origin) = leave_view(paths, sid, &chat, projects, &mac_cwd, n, &rules, build)?;
    let outcome = if up.resumed { "resumed" } else { "staged" };
    let report = StageReport { session: sid.to_string(), bytes: up.bytes, parts: up.parts, key: up.key, outcome, view, origin };
    audit_stage(paths, &report, t0);
    Ok(report)
}

/// `chat`'s original in place is the copy S3 holds as `m`'s first part (a
/// `v1/<sid>/mac/<sha256>` object of its length and sha256: what
/// `workspace::transcript`'s cut-stage check takes); else the chat went on
/// here after a stage was cut, and moving it behind a view of what it is
/// now would leave S3's older copy as the chat a reopen restores: refused
/// (`Config`, exit 1), the original left in place, naming the way out — a
/// manifest of that Mac object alone is purged and staged again with every
/// local turn; one with a VM's parts has the remote turns, which a purge
/// would lose.
fn staged_copy(m: &Manifest, chat: &MacChat, sid: &str) -> Result<(), BridgeError> {
    let main = chat.main_path(sid);
    if let Some(first) = m.parts.first() {
        let mac = matches!(S3Key::parse(&first.key), Some(S3Key::Mac { .. }));
        if mac && chat.files.first().map(|(_, n)| *n) == Some(first.len) && sha256_if_len(&main, first.len)?.as_deref() == Some(first.sha256.as_str()) {
            return Ok(());
        }
    }
    if m.gen == 0 && m.parts.len() == 1 {
        return Err(BridgeError::Config(format!(
            "{} is not the copy S3 holds of {sid} (the chat went on here after a stage was cut): it stays where it is; ai-env session forget {sid} --purge, then ai-env session stage {sid}, stages it with every local turn",
            main.display()
        )));
    }
    Err(BridgeError::Config(format!(
        "{} is not the copy S3 holds of {sid}: the chat went on remotely too, and the two copies diverged; it stays where it is (a purge would lose the remote turns)",
        main.display()
    )))
}

/// A chat that did not begin on this Mac, refused (`manifest::origin_of`):
/// a VM's (its transcript is in S3 already), or an S8 mirror's, which
/// `session migrate-s9` takes.
fn refuse_other_origin(paths: &Paths, sid: &str) -> Result<(), BridgeError> {
    match manifest::origin_of(paths, sid) {
        Some(manifest::ORIGIN_VM) => Err(BridgeError::Config(format!("session {sid} began on a VM: its transcript is in S3 already (ai-env session sync {sid})"))),
        Some(manifest::ORIGIN_S8_MIRROR) => Err(BridgeError::Config(format!("session {sid} is a remote chat of S8 whose copy here is the mirror: ai-env session migrate-s9 moves it to S3"))),
        _ => Ok(()),
    }
}

/// How far into a transcript [`recorded_cwd`] looks.
const CWD_HEAD_MAX: u64 = 16 << 20;

/// The cwd the transcript at `path` records (a regular file, opened without
/// following a symlink, never blocking): that of its first entry naming an
/// absolute one within its first `CWD_HEAD_MAX` bytes, which is where the
/// chat began (a later entry may name a directory it moved to). `Ok(None)`
/// when no entry there does.
pub fn recorded_cwd(path: &Path) -> Result<Option<String>, BridgeError> {
    use std::io::{BufRead as _, Read as _};
    #[derive(Deserialize)]
    struct Entry {
        cwd: Option<String>,
    }
    let at = |what: &str, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", path.display())));
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|e| at("open", e))?;
    if !file.metadata().map_err(|e| at("stat", e))?.is_file() {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is not a regular file", path.display()))));
    }
    let mut reader = std::io::BufReader::new(file.take(CWD_HEAD_MAX));
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).map_err(|e| at("read", e))? == 0 {
            return Ok(None);
        }
        if let Ok(Entry { cwd: Some(cwd) }) = serde_json::from_slice::<Entry>(&line) {
            if Path::new(&cwd).is_absolute() {
                return Ok(Some(cwd));
            }
        }
    }
}

/// Where a chat of this Mac began, as [`chat_workspace`] found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatWorkspace {
    /// The cwd as its transcript recorded it (what Cursor used: a view's
    /// lines carry it when no row names one).
    pub recorded: String,
    /// It made canonical: the workspace P0 resolves.
    pub canonical: PathBuf,
}

/// The workspace a chat of this Mac reopens in, before any request or
/// Touch ID (`session stage`, with `--warm` or without): the cwd the chat's
/// own transcript records ([`recorded_cwd`]; a chat begun here has no remote
/// session's row yet), resolved (canonicalised, a directory), under
/// `bridge.toml`'s roots and passing P0's own resolution
/// (`workspace::resolve`, local git only: a supported git repository whose
/// top level is under the roots), as a remote session's cwd must. The
/// transcript read is the original in the projects directory when it is no
/// view, else the copy a stage kept under `origin/`. Refused, each naming
/// why: outside the roots or in no git repository (`WorkspaceRefused`, exit
/// 9, as P0 refuses a remote session there: staged, the chat could never
/// reopen, its view's local resume refused too); an unsupported repository
/// (resolve's own, exit 1); a cwd that is gone or no directory, none
/// recorded, no transcript of it left here, no such chat (`Config`, exit 1).
pub fn chat_workspace(paths: &Paths, cfg: &BridgeConfig, projects: &Path, sid: &str) -> Result<ChatWorkspace, BridgeError> {
    let row = crate::bridge::registry::read(paths, sid).ok().flatten();
    let slugs: Vec<&str> = row.as_ref().and_then(|r| r.slug.as_deref()).into_iter().collect();
    let here = crate::bridge::seed::candidates(projects, &slugs, sid).into_iter().next().map(|dir| dir.join(format!("{sid}.jsonl")));
    let kept = paths.transcript_origin(sid).join(format!("{sid}.jsonl"));
    let transcript = match here {
        Some(path) if !crate::bridge::view::is_view_file(&path) => path,
        _ if std::fs::symlink_metadata(&kept).is_ok_and(|m| m.is_file()) => kept,
        Some(view) => {
            return Err(BridgeError::Config(format!("{} is a view and the chat's transcript is not on this Mac (nor {}): where it began is unknown (ai-env vm warm <workspace> warms a workspace by hand)", view.display(), kept.display())));
        }
        None => return Err(BridgeError::Config(format!("no chat {sid} on this Mac (no {sid}.jsonl under {})", projects.display()))),
    };
    let Some(cwd) = recorded_cwd(&transcript)? else {
        return Err(BridgeError::Config(format!("{} records no cwd: where the chat began is unknown, and with it whether it could reopen remote (nothing was staged)", transcript.display())));
    };
    workspace_at(cfg, cwd)
}

/// The workspace of a chat that began in `cwd` ([`chat_workspace`]'s, or a
/// VM-begun chat's row's: [`warm_workspace`]): resolved (canonicalised, a
/// directory), under `bridge.toml`'s roots and passing P0's own resolution;
/// refused as [`chat_workspace`] says.
fn workspace_at(cfg: &BridgeConfig, cwd: String) -> Result<ChatWorkspace, BridgeError> {
    use crate::bridge::workspace::code::OUTSIDE_ROOTS;
    let canonical = std::fs::canonicalize(&cwd).map_err(|e| BridgeError::Config(format!("the chat began in {cwd}, which cannot be resolved ({e}): it could not reopen there (nothing was staged)")))?;
    if !canonical.is_dir() {
        return Err(BridgeError::Config(format!("the chat began in {cwd}, which is not a directory: it could not reopen there (nothing was staged)")));
    }
    if !crate::bridge::route::cwd_under_roots(&canonical, &cfg.roots()) {
        return Err(BridgeError::WorkspaceRefused {
            code: OUTSIDE_ROOTS,
            message: format!("the chat began in {}, outside bridge.toml's roots: no remote session runs there, so staged it could not reopen at all (a local resume of its view exits 9; nothing was staged)", canonical.display()),
        });
    }
    let shown = canonical.display().to_string();
    let context = |message: String| format!("the chat began in {shown}, where no remote session can run ({message}): staged it could never reopen (nothing was staged)");
    crate::bridge::workspace::resolve(cfg, &canonical, None).map_err(|e| match e {
        BridgeError::WorkspaceRefused { code, message } => BridgeError::WorkspaceRefused { code, message: context(message) },
        BridgeError::WorkspaceFailed { code, message } => BridgeError::WorkspaceFailed { code, message: context(message) },
        other => BridgeError::Config(context(other.to_string())),
    })?;
    Ok(ChatWorkspace { recorded: cwd, canonical })
}

/// `session stage --warm`'s workspace, before any request or Touch ID. A
/// chat that began on a VM (`manifest::origin_of`'s `vm`: S3 holds it
/// already, and `--warm` restores it, as a reopen over what it pulls inline
/// asks; S9, R5-AWS-1) reopens in the cwd its registry row records, checked
/// as a recorded cwd is ([`chat_workspace`]'s rules); a row that records
/// none is refused (`Config`, exit 1). Any other chat: the stage's own
/// refusal first (an S8 mirror, `session migrate-s9`'s), then
/// [`chat_workspace`]'s. Canonical.
pub fn warm_workspace(paths: &Paths, cfg: &BridgeConfig, projects: &Path, sid: &str) -> Result<PathBuf, BridgeError> {
    if manifest::origin_of(paths, sid) == Some(manifest::ORIGIN_VM) {
        let cwd = crate::bridge::registry::read(paths, sid).ok().flatten().and_then(|r| r.cwd).filter(|c| Path::new(c).is_absolute());
        let Some(cwd) = cwd else {
            return Err(BridgeError::Config(format!("session {sid} began on a VM and its row records no cwd: where it reopens is unknown (ai-env vm warm <workspace> warms a workspace by hand)")));
        };
        return workspace_at(cfg, cwd).map(|w| w.canonical);
    }
    refuse_other_origin(paths, sid)?;
    chat_workspace(paths, cfg, projects, sid).map(|w| w.canonical)
}

/// `session stage --warm`'s report for a chat that began on a VM (S9,
/// R5-AWS-1): S3 holds it already, so nothing is staged, unsealed or
/// audited here; `already`, from its manifest (none: nothing committed yet,
/// 0 bytes), its view the row's.
fn held_report(paths: &Paths, sid: &str) -> Result<StageReport, BridgeError> {
    let m = manifest::read(paths, sid)?;
    let view = crate::bridge::registry::read(paths, sid).ok().flatten().and_then(|r| r.view);
    let (bytes, parts, key) = match &m {
        Some(m) => (m.committed + m.files.iter().map(|f| f.len).sum::<u64>(), u32::try_from(m.parts.len()).unwrap_or(u32::MAX), m.parts.first().map(|p| p.key.clone()).unwrap_or_default()),
        None => (0, 0, String::new()),
    };
    Ok(StageReport { session: sid.to_string(), bytes, parts, key, outcome: "already", view, origin: None })
}

/// While held, this process's stdout (fd 1) is a copy of another
/// descriptor (`session stage --warm --json`: its stderr), so that what a
/// step prints as status (its `outln!` lines, its children's output) goes
/// there and a `--json` stdout keeps its one document. Dropped, fd 1 is
/// what it was.
struct StdoutTo {
    saved: std::os::fd::OwnedFd,
}

impl StdoutTo {
    fn hold(to: std::os::fd::BorrowedFd<'_>) -> std::io::Result<StdoutTo> {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        std::io::stdout().flush()?;
        // SAFETY: a close-on-exec copy of fd 1 at 3 or above; on success the new descriptor is exclusively ours.
        let fd = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just made by the fcntl above and nothing else owns it.
        let saved = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        // SAFETY: `to` is open for this call; dup2 only makes fd 1 its copy.
        if unsafe { libc::dup2(to.as_raw_fd(), 1) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(StdoutTo { saved })
    }
}

impl Drop for StdoutTo {
    fn drop(&mut self) {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        let _ = std::io::stdout().flush();
        // SAFETY: `saved` is open (owned here); dup2 only makes fd 1 its copy again.
        let _ = unsafe { libc::dup2(self.saved.as_raw_fd(), 1) };
    }
}

/// What `session stage --warm` asks of its warm (S9, R5-AWS-1): the chat to
/// restore into the VM once the warm made it ready, the Mac's projects
/// directory (the chat's copy, its view) and the slugs it is looked for
/// under besides the workspace's (its registry row's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRestore {
    pub session: String,
    pub projects: PathBuf,
    pub slugs: Vec<String>,
}

/// What the restore after the warm did ([`restore_into`]): the VM, the
/// outcome, its ms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmRestore {
    pub vm: String,
    pub outcome: crate::bridge::workspace::TranscriptOutcome,
    pub ms: u64,
}

impl WarmRestore {
    /// The bytes it pulled into the VM: none when the VM held the committed
    /// prefix already, or S3 held nothing of the chat.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        use crate::bridge::workspace::TranscriptOutcome as O;
        match self.outcome {
            O::Restored { bytes, .. } | O::Staged { bytes } => bytes,
            O::KeptOnVm | O::NothingToRestore => 0,
        }
    }

    /// The line `session stage --warm` prints for it (without `--json`).
    #[must_use]
    pub fn line(&self, sid: &str) -> String {
        use crate::bridge::workspace::TranscriptOutcome as O;
        match self.outcome {
            O::Restored { .. } | O::Staged { .. } => format!("restored {sid} from S3 into {}: {} bytes in {} ms; a reopen on this VM keeps it", self.vm, self.bytes(), self.ms),
            O::KeptOnVm => format!("{} holds {sid} as S3 committed it already: nothing pulled; a reopen on this VM keeps it", self.vm),
            O::NothingToRestore => format!("S3 holds nothing of {sid} to restore into {}", self.vm),
        }
    }
}

/// `session stage --warm`'s restore (S9, R5-AWS-1), once its warm made `vm`
/// ready (`vm::cmd`'s warm calls it last, with that VM's row and caps and
/// the workspace it seeded): `chat` restored from S3 into that VM with no
/// deadline (`workspace::transcript::restore`, as a resume miss's retry
/// restores it: any size), on the warm's API, so no Touch ID of its own;
/// audited `transcript_pull` (its bytes and ms) as a reopen's restore is,
/// the manifest then naming the VM. A VM that holds the committed prefix
/// pulls nothing (`kept`): the command can run again. The next reopen that
/// takes this VM keeps the chat (`transcript:kept`) within Cursor's window,
/// whatever its size. Never into a VM without the transcript store: the
/// warm refused one before it seeded or delivered anything (R4), and the
/// restore checks the caps again.
pub(crate) async fn restore_into<A: MicrovmApi + S3Sign + 'static>(
    ctx: &crate::bridge::vm::cmd::Ctx,
    api: &std::sync::Arc<A>,
    row: &crate::bridge::vm::registry::VmRow,
    vm: &crate::bridge::api::VmInfo,
    caps: &[String],
    ws: &crate::bridge::workspace::WorkspaceRef,
    chat: &ChatRestore,
) -> Result<WarmRestore, BridgeError> {
    use crate::bridge::workspace::{EnsureCtx, SeedLimits, SeedProgress};
    let t0 = std::time::Instant::now();
    let mut target_row = row.clone();
    if !vm.endpoint.is_empty() {
        target_row.endpoint = Some(vm.endpoint.clone());
    }
    let target = crate::bridge::agent::AgentTarget::from_row(&target_row)?;
    let (dp, tokens) = crate::bridge::remote::pipeline::data_plane(ctx, api, &vm.id, false)?;
    let sync = super::TranscriptSync::for_workspace(&ctx.paths, &ctx.cfg, &ctx.knobs, ws, &chat.projects)?;
    let progress = |p: SeedProgress| tracing::info!("restore: {p:?}");
    let ectx = EnsureCtx { api: &**api, dp: &*dp, tokens: &*tokens, paths: &ctx.paths, cfg: &ctx.cfg, target: &target, caps, ws, lim: SeedLimits::cli(&ctx.cfg, None), deadline: None, progress: &progress };
    let slugs: Vec<&str> = std::iter::once(ws.slug.as_str()).chain(chat.slugs.iter().map(String::as_str)).collect();
    let outcome = crate::bridge::workspace::transcript::restore(&ectx, &sync, Some(&chat.projects), &slugs, &chat.session, &crate::wire::view::build_view).await?;
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(session = %chat.session, vm = %vm.id, outcome = outcome.word(), ms, "session stage --warm: the chat restored into the VM");
    Ok(WarmRestore { vm: vm.id.clone(), outcome, ms })
}

/// `session stage`'s output once [`stage`] reported. Without `--json`: the
/// report's line on `out`; then, given `warm` (`ai-env vm warm` of the
/// chat's workspace, its VM started or resumed now, then the chat restored
/// into it: S9, R5-AWS-1), the warm's own lines and the restore's
/// ([`WarmRestore::line`]). With `--json`, `out` holds the one document,
/// written once the warm is done: the report and `restore` (`vm`,
/// `outcome`, `bytes`, `ms`; null without `--warm`, and when the warm or
/// the restore failed, whose error is then the command's), while the warm's
/// lines and its children's output go to `err` (fd 1 is its copy
/// meanwhile).
fn report_and_warm<W: FnOnce() -> crate::errors::Result<Option<WarmRestore>>>(report: &StageReport, json: bool, out: &mut dyn std::io::Write, err: std::os::fd::BorrowedFd<'_>, warm: Option<W>) -> crate::errors::Result<()> {
    if !json {
        let view = report.view.as_deref().map_or_else(String::new, |v| format!("; its view is {v}"));
        let origin = report.origin.as_ref().map_or_else(String::new, |p| format!("; the original is kept in {}", p.display()));
        writeln!(out, "{} {}: {} bytes, {} part(s), {}{view}{origin}", report.outcome, report.session, report.bytes, report.parts, report.key)?;
        out.flush()?;
    }
    let warmed = match warm {
        Some(warm) => {
            let _on_err = if json { Some(StdoutTo::hold(err)?) } else { None };
            warm()
        }
        None => Ok(None),
    };
    let restored = warmed.as_ref().ok().and_then(Option::as_ref);
    if json {
        let restore = restored.map(|r| serde_json::json!({ "vm": r.vm, "outcome": r.outcome.word(), "bytes": r.bytes(), "ms": r.ms }));
        let doc = serde_json::json!({
            "session": report.session, "bytes": report.bytes, "parts": report.parts, "key": report.key, "outcome": report.outcome,
            "view": report.view, "origin": report.origin.as_ref().map(|p| p.display().to_string()), "restore": restore,
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?)?;
    } else if let Some(r) = restored {
        writeln!(out, "{}", r.line(&report.session))?;
    }
    out.flush()?;
    warmed.map(drop)
}

/// The `transcript_stage` audit row of `r`.
fn audit_stage(paths: &Paths, r: &StageReport, t0: std::time::Instant) {
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let pairs = [("session", r.session.clone()), ("bytes", r.bytes.to_string()), ("parts", r.parts.to_string()), ("outcome", r.outcome.to_string()), ("ms", ms.to_string())];
    crate::bridge::workspace::audit(paths, crate::bridge::remote::audit_event::TRANSCRIPT_STAGE, &pairs);
}

/// `ai-env session stage UUID [--warm] [--json]` (plans/s9-contracts.md
/// §4.4): [`stage`] with the runtime key (the fake API's lab key under the
/// lab's knobs) and the transcripts bucket of `state/infra.toml`; then, with
/// `--warm`, `ai-env vm warm` of the chat's workspace ([`warm_workspace`]:
/// the cwd its transcript records, checked before anything else as P0
/// checks a remote session's: a git repository under the roots), which
/// starts or resumes that workspace's VM now, and the chat restored from S3
/// into that VM ([`restore_into`], no deadline: any size; S9, R5-AWS-1), so
/// its reopen there keeps it. A chat that began on a VM takes `--warm` too
/// (its workspace its row's cwd): S3 holds it, nothing is staged, the
/// report says `already`. Touch IDs: the stage's (the runtime key; none for
/// `already`), the warm's (the runtime key, the token with it when
/// `combined.env` is current), none for the restore. With `--json` stdout
/// holds the one document, the warm's lines go to stderr
/// (`report_and_warm`).
/// Exits: 0 staged, resumed or already (and with `--warm` warmed and
/// restored); 9 a finding (nothing sent), or a chat whose recorded cwd is
/// outside the roots or in no git repository (it could never reopen once
/// staged: [`chat_workspace`], with `--warm` or without); 1 no such chat,
/// one begun on a VM (without `--warm`), or an S8 mirror (`session
/// migrate-s9` takes it), one whose cwd is unknown, gone or an unsupported
/// repository, an original that is not the copy S3 holds; 2 usage; 5 no
/// runtime key; 7 S3; the warm's own.
pub fn cmd_stage(store: &Keystore, uuid: &str, warm: bool, json: bool) -> crate::errors::Result<()> {
    use crate::bridge::vm::cmd::{backend, runtime, Backend, Ctx};
    use std::os::fd::AsFd as _;
    if !crate::bridge::registry::is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let ctx = Ctx::load()?;
    let projects = crate::bridge::mirror::mac_config_dir().map(|d| d.join("projects")).ok_or_else(|| CliError::Msg("neither CLAUDE_CONFIG_DIR nor HOME is set: no projects directory to stage from".into()))?;
    let workspace = if warm { Some(warm_workspace(&ctx.paths, &ctx.cfg, &projects, uuid)?) } else { None };
    let target = S3Target::resolve(&ctx.paths, &ctx.knobs)?;
    // A chat begun on a VM is in S3 already: `--warm` restores it, with nothing to stage.
    let report = if warm && manifest::origin_of(&ctx.paths, uuid) == Some(manifest::ORIGIN_VM) {
        held_report(&ctx.paths, uuid)?
    } else {
        let rt = runtime()?;
        let unseal = || async {
            match backend(store, &ctx).await.map_err(BridgeError::Cli)? {
                Backend::Sdk(api, _) => Ok(Signer::Sdk(api)),
                Backend::Fake(f) => Ok(Signer::Fake(f)),
            }
        };
        rt.block_on(stage(&ctx.paths, &ctx.cfg, &target, &projects, uuid, MULTIPART_PART, &crate::wire::view::build_view, unseal))?
    };
    let slugs = crate::bridge::registry::read(&ctx.paths, uuid).ok().flatten().and_then(|r| r.slug).into_iter().collect();
    let chat = ChatRestore { session: uuid.to_string(), projects, slugs };
    let warm = workspace.map(|workspace| move || crate::bridge::vm::cmd::main_with(store, crate::cli::VmCmd::Warm { workspace, json: false, dry_run: false, prewarm: false }, Some(chat)));
    report_and_warm(&report, json, &mut std::io::stdout(), std::io::stderr().as_fd(), warm)
}

/// The presigner a command unsealed: the runtime key, or the fake API's lab key.
pub enum Signer {
    Sdk(std::sync::Arc<crate::bridge::vm::client::SdkMicrovmApi>),
    Fake(crate::bridge::vm::fake_file::FileFakeMicrovmApi),
}

impl S3Sign for Signer {
    async fn presign(&self, req: &super::PresignReq) -> Result<crate::wire::s3::PresignedUrl, BridgeError> {
        match self {
            Signer::Sdk(api) => api.presign(req).await,
            Signer::Fake(f) => f.presign(req).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// plans/s9-contracts.md §5.8's sample stage file reads and writes back.
    #[test]
    fn the_sample_stage_file_reads_and_round_trips() {
        let text = r#"v = 1
session = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
key = "v1/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/mac/756ad326b9d0e363b1359566e1992e0bcdaa19c4939f0c7ad890dcfea3f9fd4a"
upload_id = "fu1"
len = 2147483648
sha256 = "756ad326b9d0e363b1359566e1992e0bcdaa19c4939f0c7ad890dcfea3f9fd4a"
part_len = 67108864
started = "2026-10-17T10:15:30Z"

[[parts]]
number = 1
len = 67108864
sha256 = "841075eede78b44b2d2862f4c38a643daf938671983e4ca0563a98a82ceddcd1"
etag = "\"0123456789abcdef0123456789abcdef\""
"#;
        let s: Stage = toml::from_str(text).unwrap();
        assert_eq!((s.v, s.part_len, s.parts.len(), s.parts[0].etag.as_str()), (STAGE_V, crate::wire::s3::MULTIPART_PART, 1, "\"0123456789abcdef0123456789abcdef\""));
        assert!(matches!(crate::wire::s3::S3Key::parse(&s.key), Some(crate::wire::s3::S3Key::Mac { .. })));
        assert_eq!(toml::from_str::<Stage>(&toml::to_string(&s).unwrap()).unwrap(), s);
    }
}

#[cfg(test)]
mod g4_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A move across volumes streams the file into a 0600 temp file beside
    /// the target, then renames it over (no temp file left); a symlink at the
    /// target and a source that is no regular file are refused, the source
    /// kept. The length-gated sha256 reads only a file of exactly that length.
    #[test]
    fn a_copy_across_volumes_streams_into_place() {
        let tmp = tempfile::tempdir().unwrap();
        let (from, to) = (tmp.path().join("a.jsonl"), tmp.path().join("origin/a.jsonl"));
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        let bytes: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&from, &bytes).unwrap();
        std::fs::write(&to, b"an older copy").unwrap();
        copy_across(&from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&to).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(from.exists(), "the caller removes the source");
        assert_eq!(std::fs::read_dir(to.parent().unwrap()).unwrap().count(), 1, "no temp file left");
        let link = tmp.path().join("origin/link.jsonl");
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), &link).unwrap();
        assert!(copy_across(&from, &link).is_err() && !tmp.path().join("elsewhere").exists(), "never through a symlink");
        assert!(copy_across(tmp.path(), &to).is_err(), "a directory is no regular file");
        assert_eq!(std::fs::read_dir(to.parent().unwrap()).unwrap().count(), 2, "nothing left behind by a refusal");
        use sha2::{Digest, Sha256};
        assert_eq!(sha256_if_len(&from, bytes.len() as u64).unwrap(), Some(hex::encode(Sha256::digest(&bytes))));
        assert_eq!(sha256_if_len(&from, bytes.len() as u64 - 1).unwrap(), None, "another length: nothing read");
        assert!(sha256_if_len(&link, 1).is_err(), "a symlink is never followed");
    }

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// `session stage --warm --json`: stdout holds exactly the one JSON
    /// document, written once the warm and its restore are done, its
    /// `restore` their facts (R5-AWS-1: the VM, the outcome, the bytes, the
    /// ms); the warm's own lines (`outln!`, as `vm warm` prints them) go to
    /// stderr (a file stands in for it), and fd 1 is stdout again after. A
    /// warm that failed still leaves the document (`restore` null) and its
    /// error is the exit. Without `--json` the report is its line, then the
    /// restore's (`kept`: nothing pulled); without `--warm`, the one line.
    #[test]
    fn under_warm_json_stdout_holds_the_one_document() {
        use crate::bridge::workspace::TranscriptOutcome;
        use std::io::{Read as _, Seek as _};
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::MetadataExt as _;
        let fd1 = || {
            let m = std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned().unwrap()).metadata().unwrap();
            (m.dev(), m.ino())
        };
        let before = fd1();
        let report = StageReport { session: SID.into(), bytes: 600, parts: 1, key: format!("v1/{SID}/mac/{}", "a".repeat(64)), outcome: "staged", view: Some(format!("-w/{SID}.jsonl")), origin: Some(PathBuf::from("/s/origin")) };
        let mut err = tempfile::tempfile().unwrap();
        let mut out = Vec::new();
        let restored = WarmRestore { vm: "microvm-1".into(), outcome: TranscriptOutcome::Restored { parts: 1, bytes: 600 }, ms: 42 };
        let warm = || -> crate::errors::Result<Option<WarmRestore>> {
            crate::outln!("microvm-1 now holds the setup-token (seal t1): credentialed commands there need no Touch ID for it until the VM is suspended");
            crate::outln!("microvm-1: the workspace's checkout seeded");
            Ok(Some(restored.clone()))
        };
        report_and_warm(&report, true, &mut out, err.as_fd(), Some(warm)).unwrap();
        assert_eq!(fd1(), before, "fd 1 is stdout again");
        let doc: serde_json::Value = serde_json::from_slice(&out).expect("stdout: exactly one JSON document");
        assert_eq!((doc["session"].as_str(), doc["outcome"].as_str(), doc["origin"].as_str()), (Some(SID), Some("staged"), Some("/s/origin")));
        assert_eq!(doc["restore"], serde_json::json!({ "vm": "microvm-1", "outcome": "restored", "bytes": 600, "ms": 42 }), "{doc}");
        let mut text = String::new();
        err.rewind().unwrap();
        err.read_to_string(&mut text).unwrap();
        for want in ["microvm-1 now holds the setup-token", "microvm-1: the workspace's checkout seeded"] {
            assert!(text.contains(want), "stderr lacks {want:?}: {text}");
        }
        // The warm failed: the document all the same, `restore` null, the warm's exit.
        let mut out = Vec::new();
        let failed = || -> crate::errors::Result<Option<WarmRestore>> { Err(CliError::Aws("s3 transcript pull: HTTP 403".into())) };
        let e = report_and_warm(&report, true, &mut out, err.as_fd(), Some(failed)).unwrap_err();
        assert_eq!(e.exit_code(), 7);
        let doc: serde_json::Value = serde_json::from_slice(&out).expect("stdout: exactly one JSON document");
        assert!(doc["restore"].is_null() && doc["outcome"] == "staged", "{doc}");
        // Without --json: the report's line, then the restore's.
        let mut out = Vec::new();
        let kept = || -> crate::errors::Result<Option<WarmRestore>> { Ok(Some(WarmRestore { vm: "microvm-1".into(), outcome: TranscriptOutcome::KeptOnVm, ms: 7 })) };
        report_and_warm(&report, false, &mut out, err.as_fd(), Some(kept)).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[1], format!("microvm-1 holds {SID} as S3 committed it already: nothing pulled; a reopen on this VM keeps it"));
        assert_eq!(restored.line(SID), format!("restored {SID} from S3 into microvm-1: 600 bytes in 42 ms; a reopen on this VM keeps it"));
        let mut out = Vec::new();
        report_and_warm(&report, false, &mut out, err.as_fd(), None::<fn() -> crate::errors::Result<Option<WarmRestore>>>).unwrap();
        let line = String::from_utf8(out).unwrap();
        assert!(line.starts_with(&format!("staged {SID}: 600 bytes, 1 part(s), v1/{SID}/mac/")) && line.ends_with("; the original is kept in /s/origin\n") && line.lines().count() == 1, "{line}");
    }

    /// `session stage --warm`'s workspace is the cwd the chat's own
    /// transcript records (its first entry naming one, not a later one),
    /// with no registry row at all (a chat begun here, no remote session
    /// yet), resolved through a symlink, under the roots and a git
    /// repository P0 accepts; once staged it is read from `origin/`, the
    /// view standing in the projects directory. Refused, each naming why: a
    /// cwd outside the roots (never advised to stage) and a plain directory
    /// under them (no git repository) exit 9, as P0 refuses a remote
    /// session there (the lead's phase-4 item 3); one that is gone, none
    /// recorded, no chat exit 1. A chat that began on a VM takes its row's
    /// cwd under the same rules (none recorded: exit 1); an S8 mirror is the
    /// stage's own refusal (exit 1, naming `session migrate-s9`).
    #[test]
    fn warm_takes_the_workspace_from_the_chats_own_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let (work, elsewhere) = (tmp.path().join("work"), tmp.path().join("elsewhere"));
        let (repo, notes) = (work.join("repo"), work.join("notes"));
        for d in [repo.join("sub"), notes.clone(), elsewhere.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        for args in [&["init", "-q"][..], &["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "i"]] {
            let o = std::process::Command::new("git").args(args).current_dir(&repo).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        }
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&repo, &link).unwrap();
        let cfg = BridgeConfig::parse(&format!("[workspaces]\nroots = [{:?}]\n", work)).unwrap();
        let projects = tmp.path().join("projects");
        let main = projects.join("-w-repo").join(format!("{SID}.jsonl"));
        std::fs::create_dir_all(main.parent().unwrap()).unwrap();
        let chat = |cwds: &[&Path]| {
            let mut text = String::from("{\"type\":\"summary\",\"summary\":\"no cwd here\"}\n{\"type\":\"user\",\"cwd\":\"relative/is/skipped\"}\n");
            for cwd in cwds {
                text.push_str(&serde_json::json!({"type": "user", "cwd": cwd, "sessionId": SID, "message": {"role": "user", "content": "hi"}}).to_string());
                text.push('\n');
            }
            std::fs::write(&main, text).unwrap();
        };
        let refused_with = |why: &str, exit: i32| {
            let e = warm_workspace(&paths, &cfg, &projects, SID).expect_err(why);
            assert!(e.to_string().contains(why), "{why}: {e}");
            assert_eq!(CliError::from(e).exit_code(), exit, "{why}");
        };
        let refused = |why: &str| refused_with(why, 1);
        let canonical = std::fs::canonicalize(&repo).unwrap();
        refused(&format!("no chat {SID} on this Mac"));
        chat(&[repo.as_path(), repo.join("sub").as_path()]);
        assert!(crate::bridge::registry::read(&paths, SID).unwrap().is_none(), "no registry row");
        assert_eq!(warm_workspace(&paths, &cfg, &projects, SID).unwrap(), canonical, "the first cwd recorded");
        chat(&[link.as_path()]);
        assert_eq!(warm_workspace(&paths, &cfg, &projects, SID).unwrap(), canonical, "resolved through the symlink");
        chat(&[elsewhere.as_path()]);
        refused_with("outside bridge.toml's roots: no remote session runs there, so staged it could not reopen at all (a local resume of its view exits 9; nothing was staged)", 9);
        chat(&[notes.as_path()]);
        refused_with("where no remote session can run (", 9);
        refused_with("not a git repository", 9);
        chat(&[work.join("gone").as_path()]);
        refused("which cannot be resolved");
        chat(&[]);
        refused("records no cwd");
        // Staged: the original under origin/, the view in its place.
        chat(&[repo.as_path()]);
        let kept = paths.transcript_origin(SID).join(format!("{SID}.jsonl"));
        std::fs::create_dir_all(kept.parent().unwrap()).unwrap();
        std::fs::rename(&main, &kept).unwrap();
        std::fs::write(&main, b"{\"aiEnvView\":1,\"type\":\"ai-title\",\"aiTitle\":\"t\"}\n").unwrap();
        assert_eq!(warm_workspace(&paths, &cfg, &projects, SID).unwrap(), canonical, "read from origin/");
        std::fs::remove_file(&kept).unwrap();
        refused("is a view and the chat's transcript is not on this Mac");
        // S9 R5-AWS-1: a chat that began on a VM (S3 holds it) reopens in its row's cwd, checked as a recorded one;
        // a row that records none is refused, and an S8 mirror is still the stage's own refusal (migrate-s9 first).
        let row = crate::bridge::registry::SessionRow { session_id: SID.into(), mode: "remote".into(), transcript_home: Some(manifest::HOME_S3.into()), cwd: Some(link.display().to_string()), ..crate::bridge::registry::SessionRow::default() };
        crate::bridge::registry::write(&paths, &row).unwrap();
        assert_eq!(warm_workspace(&paths, &cfg, &projects, SID).unwrap(), canonical, "a VM-begun chat: its row's cwd");
        crate::bridge::registry::write(&paths, &crate::bridge::registry::SessionRow { cwd: Some(notes.display().to_string()), ..row.clone() }).unwrap();
        refused_with("not a git repository", 9);
        crate::bridge::registry::write(&paths, &crate::bridge::registry::SessionRow { cwd: None, ..row.clone() }).unwrap();
        refused(&format!("session {SID} began on a VM and its row records no cwd"));
        crate::bridge::registry::write(&paths, &crate::bridge::registry::SessionRow { transcript_home: None, ..row }).unwrap();
        refused("ai-env session migrate-s9 moves it to S3");
    }
}
