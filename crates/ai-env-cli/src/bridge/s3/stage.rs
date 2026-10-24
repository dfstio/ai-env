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
//! S10 (F5): each request is held to its progress (`client::Waits`), not a
//! budget; a Complete whose answer was lost, or an upload S3 no longer
//! knows, is done once S3 lists the key at its length; an upload below
//! `dataplane::MIN_RATE` warns once, and `transcript_stage` records its
//! `rate`. S10 (F3a): `--warm` with `[vm].reuse_per_workspace` off is
//! refused before any Touch ID. S11 (L5, the compressed stage): `session
//! stage` stores each file as `/usr/bin/gzip -n -6` of its scanned bytes
//! (a spool under `state/transcripts/<sid>/spool/`, made again on a resume:
//! the same bytes, the same key), `Content-Encoding: gzip`, keyed by the
//! stored bytes' sha256; the manifest keeps the decoded `len` and `sha256`
//! beside `encoding`, `stored_len` and `stored_sha256`. The subtree's files
//! go up [`SUBTREE_PARALLEL`] at a time (identity ones too); a file that
//! needs multipart goes alone.
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
use crate::wire::workspace::PartEncoding;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// S11 (L5, C.3.4): the compressor of a gzip stage, run by its absolute path.
pub const GZIP: &str = "/usr/bin/gzip";

/// The chunk a file is fed to gzip in, and a spool digested in.
const FEED_CHUNK: usize = 1 << 20;

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

/// The largest chat `session stage` takes, in all and decoded (S11, C.3.5:
/// was `PULL_MAX`; each file is held to [`STAGE_FILE_MAX`]).
pub const STAGE_MAX: u64 = 16 << 30;

/// S11 (C.3.5): the largest file of a chat `session stage` takes, decoded:
/// what one pull from the VM can restore (`PULL_MAX`).
pub const STAGE_FILE_MAX: u64 = crate::wire::workspace::PULL_MAX;

/// S11 (L5, C.3.4): how many subtree files go up at once (the main goes
/// alone, first; a file that needs multipart goes alone too). Equal to
/// `wire::s3::MULTIPART_PARALLEL`.
pub const SUBTREE_PARALLEL: usize = 8;

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
/// `TranscriptTooLarge`, exit 9); S11: a file over [`STAGE_FILE_MAX`],
/// whatever `cap`, is `TranscriptTooLarge` with that file's bytes.
/// `Ok(None)`: no such chat on this Mac.
pub fn locate(projects: &Path, slugs: &[&str], sid: &str, cap: u64) -> Result<Option<MacChat>, BridgeError> {
    let Some(dir) = crate::bridge::seed::candidates(projects, slugs, sid).into_iter().next() else { return Ok(None) };
    let slug = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let files = crate::bridge::seed::transcript_files_capped(&dir, sid, cap)?;
    if let Some((_, bytes)) = files.iter().find(|(_, len)| *len > STAGE_FILE_MAX) {
        return Err(BridgeError::TranscriptTooLarge { session: sid.to_string(), bytes: *bytes });
    }
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
    /// S10 (F5): the bytes this upload sent (the parts S3 answered; none sent again for a part S3 held).
    pub sent: u64,
}

/// The latency a stage's pace allows before it is judged below
/// `dataplane::MIN_RATE` ([`below_min_rate`]): a few requests' round trips,
/// which a small chat's upload is mostly made of.
const PACE_SLACK: std::time::Duration = std::time::Duration::from_secs(2);

/// Whether `sent` bytes in `ms` milliseconds ran below
/// `dataplane::MIN_RATE` (1 MB/s), [`PACE_SLACK`] allowed for the requests'
/// latency: the bytes took longer than at that rate by more than the slack.
fn below_min_rate(sent: u64, ms: u64) -> bool {
    let at_min = sent.saturating_mul(1000) / crate::bridge::dataplane::MIN_RATE;
    sent > 0 && ms > at_min.saturating_add(u64::try_from(PACE_SLACK.as_millis()).unwrap_or(u64::MAX))
}

/// S10 (F5): the pace of one chat's upload. Its files' bytes are counted as
/// S3 answers their parts (`sent`, the report's rate), and as the connection
/// takes them, the parts in flight too (`handed`, `S3Client::counting`):
/// judged on what was handed each time a file or a part lands, the pace
/// warns once it falls below `dataplane::MIN_RATE` ([`below_min_rate`]),
/// once. Judged on the answers alone, eight parts side by side would count
/// one part's bytes over the time all eight took. No budget cuts a slow
/// upload that moves any more (`client::Waits`); the warning says why it
/// takes long.
struct Pace<'a> {
    sid: &'a str,
    started: std::time::Instant,
    sent: std::sync::atomic::AtomicU64,
    handed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    warned: std::sync::atomic::AtomicBool,
}

impl<'a> Pace<'a> {
    fn new(sid: &'a str) -> Pace<'a> {
        Pace {
            sid,
            started: std::time::Instant::now(),
            sent: std::sync::atomic::AtomicU64::new(0),
            handed: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sent(&self) -> u64 {
        self.sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `n` bytes more landed: the warning, the first time what the
    /// connections took (never less than what landed) is below the rate.
    fn add(&self, n: u64) {
        use std::sync::atomic::Ordering;
        let sent = self.sent.fetch_add(n, Ordering::Relaxed).saturating_add(n);
        let handed = self.handed.load(Ordering::Relaxed).max(sent);
        let ms = self.ms();
        if below_min_rate(handed, ms) && !self.warned.swap(true, Ordering::Relaxed) {
            let min = crate::bridge::dataplane::MIN_RATE / 1000;
            crate::bridge::voice::warn(&format!("the upload of {} runs at {} ({handed} bytes in {} s), below the {min} kB/s ai-env's transfer budgets assume; it goes on", self.sid, shown_rate(rate_of(handed, ms)), ms / 1000));
        }
    }
}

/// `sent` bytes in `ms` milliseconds, in bytes per second.
fn rate_of(sent: u64, ms: u64) -> u64 {
    sent.saturating_mul(1000) / ms.max(1)
}

/// A rate as the warning shows it: `kB/s` from 10 kB/s, else `B/s`.
fn shown_rate(bytes_per_s: u64) -> String {
    if bytes_per_s >= 10_000 {
        format!("{} kB/s", bytes_per_s / 1000)
    } else {
        format!("{bytes_per_s} B/s")
    }
}

/// Upload `path` (its digest `d`) as `key` through `client`: one part is a
/// PutObject; more are a multipart upload of `part_len` parts, at most
/// `MULTIPART_PARALLEL` at once, each streamed from the file with its signed
/// sha256, each held to its own progress (`client::Waits`), resumable
/// through `stage.toml` (the parts S3 lists with the expected size and
/// checksum are not sent again; an upload S3 no longer knows is done when S3
/// lists the key at its length, its Complete's answer lost, else it starts
/// over), completed new-only, `stage.toml` removed after. A part, the
/// PutObject or the Complete that gets no answer (or S3's 500 or 503, or a
/// transient 409) goes again, `client::PART_TRIES` tries in all. A part that
/// fails for good starts no other: the parts in flight finish, those that
/// went through are kept in `stage.toml` (a resume does not send them
/// again), then the first failure is the error.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str, key: &str, path: &Path, d: &FileDigest, part_len: u64) -> Result<Uploaded, BridgeError> {
    upload_paced(client, paths, sid, key, path, d, part_len, &Pace::new(sid), None).await
}

/// [`upload_file`], its bytes counted into `pace` as the connections take
/// them and as S3 answers them. S11 (L5): `encoding` is how `path`'s bytes
/// are stored (the PutObject's or the CreateMultipartUpload's
/// `content-encoding`); `d` is always their own digest (a spool's).
#[allow(clippy::too_many_arguments)]
async fn upload_paced<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str, key: &str, path: &Path, d: &FileDigest, part_len: u64, pace: &Pace<'_>, encoding: Option<PartEncoding>) -> Result<Uploaded, BridgeError> {
    use futures_util::StreamExt as _;
    let counted = client.counting(&pace.handed);
    let client = &counted;
    let part_len = part_len.max(1);
    if d.parts.len() <= 1 {
        let w = client.put_object(key, Body::File { path: path.to_path_buf(), offset: 0, len: d.len }, d.len, &d.sha256, encoding).await?;
        pace.add(d.len);
        return Ok(match w {
            Written::Stored(v) => Uploaded { version_id: v, parts: 1, resumed: false, existed: false, sent: d.len },
            Written::Exists => Uploaded { version_id: String::new(), parts: 1, resumed: false, existed: true, sent: d.len },
        });
    }
    let count = u32::try_from(d.parts.len()).map_err(|_| BridgeError::Config(format!("{key}: more than {} parts", u32::MAX)))?;
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
            let upload_id = client.create_multipart(key, encoding).await?;
            let s = Stage { v: STAGE_V, session: sid.to_string(), key: key.to_string(), upload_id, len: d.len, sha256: d.sha256.clone(), part_len, started: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), parts: Vec::new() };
            write_stage(paths, &s)?;
            s
        }
    };
    if resumed {
        match client.list_parts(key, &stage.upload_id).await? {
            None => {
                // S3 knows the upload no more: its Complete made the object and the answer was lost (or the run
                // was cut before `stage.toml` went), or S3's lifecycle aborted it. The key is the bytes' sha256: a
                // listing of it at their length says done before every part goes again.
                if client.holds(key, d.len).await? {
                    crate::bridge::registry::remove_if_present(&paths.transcript_stage(sid))?;
                    return Ok(Uploaded { version_id: String::new(), parts: count, resumed: true, existed: true, sent: 0 });
                }
                resumed = false;
                stage.upload_id = client.create_multipart(key, encoding).await?;
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
    let done: std::collections::BTreeSet<u32> = stage.parts.iter().map(|p| p.number).collect();
    let upload_id = stage.upload_id.clone();
    let missing: Vec<u32> = (1..=count).filter(|n| !done.contains(n)).collect();
    // Once a part failed no other starts; the parts in flight then finish (each held to its own progress) and the
    // ones that went through stay in `stage.toml`, so a resume sends only what S3 lacks.
    let failed = std::cell::Cell::new(false);
    // The parts in flight share the uplink; each is held to its own progress (`client::Waits`), never to a budget.
    let sends = missing.into_iter().take_while(|_| !failed.get()).map(|n| {
        let (upload_id, sha) = (upload_id.clone(), d.parts[n as usize - 1].clone());
        let offset = u64::from(n - 1) * part_len;
        let len = part_len.min(d.len - offset);
        async move {
            let etag = client.upload_part(key, &upload_id, n, Body::File { path: path.to_path_buf(), offset, len }, len, &sha).await?;
            Ok::<StagePart, BridgeError>(StagePart { number: n, len, sha256: sha, etag })
        }
    });
    let mut running = futures_util::stream::iter(sends).buffer_unordered(MULTIPART_PARALLEL);
    let (mut sent, mut first_error) = (0u64, None);
    while let Some(part) = running.next().await {
        let part = match part {
            Ok(part) => part,
            Err(e) => {
                failed.set(true);
                first_error.get_or_insert(e);
                continue;
            }
        };
        sent += part.len;
        pace.add(part.len);
        stage.parts.push(part);
        stage.parts.sort_by_key(|p| p.number);
        write_stage(paths, &stage)?;
    }
    drop(running);
    if let Some(e) = first_error {
        return Err(e);
    }
    let list: Vec<(u32, String, String)> = stage.parts.iter().map(|p| (p.number, p.etag.clone(), p.sha256.clone())).collect();
    let w = client.complete_multipart(key, &upload_id, &list, d.len).await?;
    crate::bridge::registry::remove_if_present(&paths.transcript_stage(sid))?;
    Ok(match w {
        Written::Stored(v) => Uploaded { version_id: v, parts: count, resumed, existed: false, sent },
        Written::Exists => Uploaded { version_id: String::new(), parts: count, resumed, existed: true, sent },
    })
}

/// What a chat's upload left: the manifest to write (`origin = "mac"`), and
/// for the report the main object's key, the bytes, the parts, whether it
/// resumed, whether S3 held it already; S10 (F5) its pace: the bytes it
/// sent, its milliseconds, and whether it ran below `dataplane::MIN_RATE`
/// (warned, once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatUpload {
    pub manifest: Manifest,
    pub key: String,
    pub bytes: u64,
    pub parts: u32,
    pub resumed: bool,
    pub existed: bool,
    pub sent: u64,
    pub ms: u64,
    pub slow: bool,
    /// S11 (C.3.7): every file's stored bytes, summed, whether sent now or held by S3 already (the raw bytes when
    /// identity).
    pub stored: u64,
    /// S11: how the files are stored (`None`: identity).
    pub encoding: Option<PartEncoding>,
}

impl ChatUpload {
    /// Its bytes sent per second (the `transcript_stage` row's `rate`).
    #[must_use]
    pub fn rate(&self) -> u64 {
        rate_of(self.sent, self.ms)
    }
}

/// S11 (L5): a spool of the stage (`state/transcripts/<sid>/spool/<n>.gz`):
/// the file gzip wrote there, held open (its inode, and so its identity
/// `dev`, `ino`, is never reused while the spool lives); removed once dropped
/// (when its object is complete, stored or held by S3 already, on any error,
/// and when its upload is cut short), and only while its path still names
/// that file: another upload of the session (one cut short whose gzip still
/// runs on its blocking thread) may have made its own there. A spool is
/// never trusted as a run left it: a resume makes it again.
struct Spool {
    path: PathBuf,
    file: std::fs::File,
    id: (u64, u64),
}

impl Spool {
    /// Whether its path still names the file this spool made.
    fn intact(&self) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.id)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        if self.intact() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// S11: the lock one upload of a session holds for its whole run
/// (`state/transcripts/<sid>/upload.lock`, [`upload_chat`]): its spools and
/// its `stage.toml` are the session's, so a second upload is refused while
/// it is held, never run beside it.
#[must_use]
pub fn upload_lock(paths: &Paths, sid: &str) -> PathBuf {
    paths.transcript_dir(sid).join("upload.lock")
}

/// One file of a chat ready to go up ([`upload_chat`]): its key
/// (`v1/<sid>/mac/<the stored bytes' sha256>`), the path whose bytes go (the
/// file itself, or its spool), the stored bytes' digest (the scan's when
/// identity), and its spool.
struct Ready {
    key: String,
    path: PathBuf,
    stored: FileDigest,
    spool: Option<Spool>,
}

/// One file of a chat once it went up (or S3 held it): its key, its stored
/// bytes' length and sha256, what the upload did.
struct Sent {
    key: String,
    stored_len: u64,
    stored_sha256: String,
    up: Uploaded,
}

/// S11 (L5, C.3.4): `chat`'s file `rel` (at `file`; `len` bytes of sha256
/// `sha256`, as the scan read them) through `/usr/bin/gzip -n -6 -c` into its
/// spool, `state/transcripts/<sid>/spool/<n>.gz` (`n` the file's index in
/// the chat, 0 the main; the directory a real 0700 one; a leftover of that
/// name removed; created 0600 with `O_EXCL | O_NOFOLLOW`). The file is read
/// without following a symlink, never blocking, exactly `len` bytes of it fed
/// to gzip's stdin and hashed on the way; gzip runs by its absolute path, its
/// environment cleared but `LC_ALL=C`, its stdout the spool, its stderr kept.
/// Fed bytes that are not the scan's are `WorkspaceFailed { changed }` (exit
/// 1); a gzip that fails, `Io` naming it, its exit and its stderr's last line,
/// scrubbed (exit 1); either way the spool goes. The spool and its digest:
/// its sha256 and its `part_len` parts' (no tripwires: its raw bytes were
/// scanned), read through the handle gzip's stdout was made from, never
/// through the path (which another run may have taken over: the bytes this
/// digest signs are then the only ones S3 accepts).
#[allow(clippy::too_many_arguments)]
fn spool_file(paths: &Paths, sid: &str, n: usize, file: &Path, rel: &str, len: u64, sha256: &str, part_len: u64) -> Result<(Spool, FileDigest), BridgeError> {
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::process::ExitStatusExt as _;
    let io = |what: &str, p: &Path, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", p.display())));
    // gzip's own failures are never a broken pipe of ours (that exit is 0): `Other`.
    let gzip_failed = |text: String| BridgeError::Io(std::io::Error::other(text));
    let dir = paths.transcript_spool(sid);
    crate::bridge::registry::ensure_private_dir(&dir)?;
    let at = dir.join(format!("{n}.gz"));
    crate::bridge::registry::remove_if_present(&at)?;
    let out = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&at).map_err(|e| io("create", &at, e))?;
    let id = match out.metadata() {
        Ok(m) => (m.dev(), m.ino()),
        Err(e) => {
            let _ = std::fs::remove_file(&at);
            return Err(io("stat", &at, e));
        }
    };
    let mut spool = Spool { path: at, file: out, id };
    let to_gzip = spool.file.try_clone().map_err(|e| io("open", &spool.path, e))?;
    let src = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(file).map_err(|e| io("open", file, e))?;
    if !src.metadata().map_err(|e| io("stat", file, e))?.is_file() {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is not a regular file", file.display()))));
    }
    let mut child = std::process::Command::new(GZIP)
        .args(["-n", "-6", "-c"])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(to_gzip))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| gzip_failed(format!("cannot run {GZIP}: {e}")))?;
    let stderr = child.stderr.take();
    let said = std::thread::spawn(move || {
        let mut text = Vec::new();
        if let Some(mut e) = stderr {
            let _ = e.read_to_end(&mut text);
        }
        text
    });
    let mut stdin = child.stdin.take();
    let (mut hasher, mut fed, mut buf) = (Sha256::new(), 0u64, vec![0u8; FEED_CHUNK]);
    let (mut reader, mut unread, mut stopped) = (src.take(len), None, false);
    loop {
        let k = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                unread = Some(e);
                break;
            }
        };
        hasher.update(&buf[..k]);
        fed += k as u64;
        if stdin.as_mut().is_some_and(|pipe| pipe.write_all(&buf[..k]).is_err()) {
            stopped = true;
            break;
        }
    }
    drop(stdin);
    let status = child.wait().map_err(|e| gzip_failed(format!("cannot wait for {GZIP}: {e}")))?;
    let stderr = said.join().unwrap_or_default();
    if let Some(e) = unread {
        return Err(io("read", file, e));
    }
    if stopped || !status.success() {
        let how = match (status.code(), status.signal()) {
            _ if status.success() => "stopped reading its input".to_string(),
            (Some(code), _) => format!("exited {code}"),
            (None, Some(signal)) => format!("was ended by signal {signal}"),
            (None, None) => "failed".to_string(),
        };
        let last = String::from_utf8_lossy(&stderr).lines().map(str::trim).rfind(|l| !l.is_empty()).map(|l| format!(": {}", crate::wire::redact::scrub(l))).unwrap_or_default();
        return Err(gzip_failed(format!("{GZIP} {how} while it compressed {rel}{last}")));
    }
    // A file that grew while it was fed (a turn appended: GZ-1) is no longer the scan's either.
    let grew = !reader.get_ref().metadata().is_ok_and(|m| m.len() == len);
    if fed != len || hex::encode(hasher.finalize()) != sha256 || grew {
        return Err(BridgeError::WorkspaceFailed {
            code: crate::wire::workspace::refusal::CHANGED,
            message: format!("the chat changed while it was staged: {rel} is not the bytes the scan read; nothing of it was sent (ai-env session stage {sid} again once the chat is closed)"),
        });
    }
    let stored = digest_spool(&mut spool.file, &spool.path, part_len)?;
    Ok((spool, stored))
}

/// The digest of the spool `file` (at `path`, for messages), read from its
/// start: its length, its sha256 and the sha256 of each `part_len` part (a
/// multipart upload's), no fingerprint, no hits.
fn digest_spool(file: &mut std::fs::File, path: &Path, part_len: u64) -> Result<FileDigest, BridgeError> {
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Seek as _};
    let at = |what: &str, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", path.display())));
    file.seek(std::io::SeekFrom::Start(0)).map_err(|e| at("read", e))?;
    let part_len = part_len.max(1);
    let (mut whole, mut part, mut in_part, mut parts, mut len) = (Sha256::new(), Sha256::new(), 0u64, Vec::new(), 0u64);
    let mut buf = vec![0u8; FEED_CHUNK];
    loop {
        let k = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(at("read", e)),
        };
        whole.update(&buf[..k]);
        let mut rest = &buf[..k];
        while !rest.is_empty() {
            let take = usize::try_from((part_len - in_part).min(rest.len() as u64)).unwrap_or(rest.len());
            part.update(&rest[..take]);
            in_part += take as u64;
            rest = &rest[take..];
            if in_part == part_len {
                parts.push(hex::encode(std::mem::replace(&mut part, Sha256::new()).finalize()));
                in_part = 0;
            }
        }
        len += k as u64;
    }
    if in_part > 0 {
        parts.push(hex::encode(part.finalize()));
    }
    Ok(FileDigest { len, sha256: hex::encode(whole.finalize()), fp: String::new(), parts, hits: Vec::new(), peak: 0 })
}

/// `chat.files[n]` (its digest `d`) ready to go up: with no encoding the
/// file itself, keyed by its own sha256; gzip, its spool ([`spool_file`], on
/// a blocking thread), keyed by the spool's.
async fn ready(paths: &Paths, sid: &str, chat: &MacChat, n: usize, d: &FileDigest, part_len: u64, encoding: Option<PartEncoding>) -> Result<Ready, BridgeError> {
    let rel = chat.files[n].0.clone();
    let file = chat.dir.join(&rel);
    let key = |sha: &str| S3Key::Mac { session: sid.to_string(), sha256: sha.to_string() }.render();
    match encoding {
        None => Ok(Ready { key: key(&d.sha256), path: file, stored: d.clone(), spool: None }),
        Some(PartEncoding::Gzip) => {
            let (paths, owned, len, sha) = (paths.clone(), sid.to_string(), d.len, d.sha256.clone());
            let (spool, stored) = crate::bridge::workspace::blocking(move || spool_file(&paths, &owned, n, &file, &rel, len, &sha, part_len)).await??;
            Ok(Ready { key: key(&stored.sha256), path: spool.path.clone(), stored, spool: Some(spool) })
        }
    }
}

/// `r` sent as [`upload_paced`] sends a file (`encoding` its
/// `content-encoding`), unless `held` (the session's listing) holds its key at
/// its stored length already: not sent again, its version unknown, as after
/// a 412. A spool whose path no longer names it (another run made its own
/// there) is refused before any request. Its spool goes after, whatever came
/// of it.
#[allow(clippy::too_many_arguments)]
async fn put_ready<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str, r: Ready, held: &[super::client::Listed], part_len: u64, pace: &Pace<'_>, encoding: Option<PartEncoding>) -> Result<Sent, BridgeError> {
    let up = if held.iter().any(|o| o.key == r.key && o.size == r.stored.len) {
        tracing::info!(session = sid, "{}: S3 holds it already: not sent again", r.key);
        Uploaded { version_id: String::new(), parts: u32::try_from(r.stored.parts.len().max(1)).unwrap_or(u32::MAX), resumed: false, existed: true, sent: 0 }
    } else {
        if r.spool.as_ref().is_some_and(|s| !s.intact()) {
            return Err(BridgeError::Busy(format!("{}: another upload of {sid} replaced this spool; nothing of it was sent", r.path.display())));
        }
        upload_paced(client, paths, sid, &r.key, &r.path, &r.stored, part_len, pace, encoding).await?
    };
    Ok(Sent { key: r.key, stored_len: r.stored.len, stored_sha256: r.stored.sha256, up })
}

/// Upload every file of `chat` (`digests` in its order, the scan's) as
/// `v1/<sid>/mac/<sha256>` objects (the main transcript as [`upload_file`]
/// does; each subtree file likewise, by its own stored bytes' sha256), and
/// build the manifest: one part (the main object), gen 0, its files by rel
/// under the chat's slug. `state/transcripts/<sid>/` is made before the
/// first request, so an upload cut before its manifest leaves a trace that
/// `forget --purge` and `gc --remote` find. One ListObjectsV2 of
/// `v1/<sid>/mac/` first: an object S3 holds already at its key with its
/// stored length (the key is its stored bytes' sha256, and only this Mac
/// writes there) is not sent again, its version unknown, as after a 412.
/// S10 (F5): its pace is judged as its files and parts land, on the bytes
/// the connections took (the parts in flight too), and an upload below
/// `dataplane::MIN_RATE` warns once (`ChatUpload::slow`). S11 (L5, C.3.4):
/// `encoding` is how the files are stored. With `Some(Gzip)` each file is
/// spooled ([`spool_file`]: its scanned bytes, a chat that changed since
/// refused) and its spool goes up with `Content-Encoding: gzip`, keyed by the
/// spool's sha256 (a resume makes the same spool: the same key, the parts S3
/// lists not sent again); the manifest's entries keep the decoded `len` and
/// `sha256` beside `encoding`, `stored_len` and `stored_sha256`. With `None`
/// the upload is S10's. Either way the main goes alone, first; then the
/// subtree's files go up to [`SUBTREE_PARALLEL`] at a time, and one whose
/// stored bytes need more than one `part_len` part (multipart: one
/// `stage.toml` per session) goes alone once the others are done; one whose
/// raw bytes exceed a part is spooled only on its turn (at most one such
/// spool on disk at once). The whole upload holds the session's
/// [`upload_lock`]: while another holds it the upload is refused (`Busy`,
/// exit 1) before any request.
#[allow(clippy::too_many_arguments)]
pub async fn upload_chat<S: S3Sign>(client: &S3Client<'_, S>, paths: &Paths, sid: &str, chat: &MacChat, digests: &[FileDigest], part_len: u64, at: &str, encoding: Option<PartEncoding>) -> Result<ChatUpload, BridgeError> {
    use futures_util::{StreamExt as _, TryStreamExt as _};
    let (Some((main_rel, _)), Some(main)) = (chat.files.first(), digests.first()) else {
        return Err(BridgeError::Config(format!("{sid}: no transcript to stage")));
    };
    if main.len == 0 {
        return Err(BridgeError::Config(format!("{}: the transcript is empty: nothing to stage", chat.dir.join(main_rel).display())));
    }
    crate::bridge::registry::ensure_private_dir(&paths.transcript_dir(sid))?;
    let lock = upload_lock(paths, sid);
    let Some(_upload) = crate::bridge::vm::lock::try_lock_exclusive(&lock)? else {
        return Err(BridgeError::Busy(format!("another upload of {sid} is under way (it holds {}); nothing was sent", lock.display())));
    };
    let pace = Pace::new(sid);
    let held: Vec<super::client::Listed> = client.list(&format!("{}{sid}/mac/", crate::wire::s3::KEY_PREFIX)).await?;
    let (held, pace) = (held.as_slice(), &pace);
    let put = |r: Ready| put_ready(client, paths, sid, r, held, part_len, pace, encoding);
    // The main alone, first.
    let first = put(ready(paths, sid, chat, 0, main, part_len, encoding).await?).await?;
    // The subtree: SUBTREE_PARALLEL files at once; one that needs multipart (or may: its raw bytes exceed a part)
    // waits, then is made ready and goes alone, so no spool of it waits on disk (a spool found to need multipart goes
    // and is made again on its turn: the same bytes). S3 holds no empty part.
    let steps = chat.files.iter().zip(digests).enumerate().skip(1).filter(|(_, (_, d))| d.len > 0).map(|(n, (_, d))| async move {
        if d.len > part_len.max(1) {
            return Ok::<(usize, Option<Sent>), BridgeError>((n, None));
        }
        let r = ready(paths, sid, chat, n, d, part_len, encoding).await?;
        Ok((n, if r.stored.parts.len() > 1 { None } else { Some(put(r).await?) }))
    });
    let mut steps: Vec<(usize, Option<Sent>)> = futures_util::stream::iter(steps).buffer_unordered(SUBTREE_PARALLEL).try_collect().await?;
    steps.sort_by_key(|(n, _)| *n);
    let mut sent: Vec<(usize, Sent)> = Vec::with_capacity(steps.len());
    for (n, step) in steps {
        let s = match step {
            Some(s) => s,
            None => put(ready(paths, sid, chat, n, &digests[n], part_len, encoding).await?).await?,
        };
        sent.push((n, s));
    }
    let stored_of = |s: &Sent| (encoding.map(|_| s.stored_len), encoding.map(|_| s.stored_sha256.clone()));
    let mut m = Manifest::new(sid, client.target(), manifest::ORIGIN_MAC, &format!("{}/{sid}.jsonl", chat.slug), at);
    let (stored_len, stored_sha256) = stored_of(&first);
    m.parts.push(ManifestPart { key: first.key.clone(), version_id: first.up.version_id.clone(), from: 0, len: main.len, sha256: main.sha256.clone(), encoding, stored_len, stored_sha256 });
    m.committed = main.len;
    m.fp = main.fp.clone();
    for (n, s) in &sent {
        let ((rel, _), d) = (&chat.files[*n], &digests[*n]);
        // A key S3 held already (a 412, or listed) takes the version another file of the chat stored it with (two
        // identical files, side by side), else none.
        let version = Some(s.up.version_id.clone()).filter(|v| !v.is_empty()).or_else(|| sent.iter().map(|(_, o)| o).find(|o| o.key == s.key && !o.up.version_id.is_empty()).map(|o| o.up.version_id.clone()));
        let (stored_len, stored_sha256) = stored_of(s);
        m.files.push(ManifestFile { rel: format!("{}/{rel}", chat.slug), key: s.key.clone(), version_id: version, len: d.len, sha256: d.sha256.clone(), encoding, stored_len, stored_sha256 });
    }
    if encoding.is_some() {
        // Every spool went with its file: the directory too (a leftover of a cut run stays, and is removed by name).
        let _ = std::fs::remove_dir(paths.transcript_spool(sid));
    }
    let stored = sent.iter().map(|(_, s)| s.stored_len).fold(first.stored_len, u64::saturating_add);
    let slow = pace.warned.load(std::sync::atomic::Ordering::Relaxed);
    Ok(ChatUpload { manifest: m, key: first.key, bytes: chat.bytes(), parts: first.up.parts, resumed: first.up.resumed, existed: first.up.existed, sent: pace.sent(), ms: pace.ms(), slow, stored, encoding })
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
    /// S10 (F5): the upload's bytes sent per second (`None`: nothing went up, `already`).
    pub rate: Option<u64>,
    /// S11 (C.3.7): the stored bytes when the stage wrote, or found (`already`), an encoded manifest; `None` else.
    pub stored: Option<u64>,
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
        let stored = m.encoded().then(|| m.stored_bytes());
        let report = StageReport { session: sid.to_string(), bytes: m.committed + m.files.iter().map(|f| f.len).sum::<u64>(), parts: 1, key: m.parts.first().map(|p| p.key.clone()).unwrap_or_default(), outcome: "already", view, origin, rate: None, stored };
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
    // S11 (L5, C.3.7): `session stage` always asks for gzip.
    let up = upload_chat(&client, paths, sid, &chat, &digests, part_len, &at, Some(PartEncoding::Gzip)).await?;
    {
        let _held = manifest::lock(paths, sid).await?;
        manifest::write(paths, &up.manifest)?;
    }
    unchanged_since_scan(&chat, &digests, sid)?;
    let (view, origin) = leave_view(paths, sid, &chat, projects, &mac_cwd, n, &rules, build)?;
    let outcome = if up.resumed { "resumed" } else { "staged" };
    let rate = (up.sent > 0).then(|| up.rate());
    let stored = up.encoding.map(|_| up.stored);
    let report = StageReport { session: sid.to_string(), bytes: up.bytes, parts: up.parts, key: up.key, outcome, view, origin, rate, stored };
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

/// GZ-1: once `chat` went up as the scan read it (`digests`), and before its
/// view replaces it, it must still be those bytes: the same files, each of
/// its scanned length, the main of its sha256 too (`staged_copy`'s rule).
/// Else the chat went on here while it was staged, and a view built from its
/// newer tail would show turns S3 never received: refused (`Config`, exit
/// 1), its files left in place and the manifest kept (S3 holds the scanned
/// bytes), naming the way out `staged_copy` names.
pub fn unchanged_since_scan(chat: &MacChat, digests: &[FileDigest], sid: &str) -> Result<(), BridgeError> {
    let main = chat.main_path(sid);
    let scanned: std::collections::BTreeMap<&str, u64> = chat.files.iter().zip(digests).map(|((rel, _), d)| (rel.as_str(), d.len)).collect();
    let now = crate::bridge::seed::transcript_files_capped(&chat.dir, sid, u64::MAX)?;
    let same_files = now.len() == scanned.len() && now.iter().all(|(rel, len)| scanned.get(rel.as_str()) == Some(len));
    if same_files {
        if let Some(d) = digests.first() {
            if sha256_if_len(&main, d.len)?.as_deref() == Some(d.sha256.as_str()) {
                return Ok(());
            }
        }
    }
    Err(BridgeError::Config(format!(
        "{} is not the copy S3 holds of {sid} (the chat went on here while it was staged): it stays where it is; ai-env session forget {sid} --purge, then ai-env session stage {sid}, stages it with every local turn",
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
    // S11 (C.3.7): an S8 mirror P3 sent up gzip-encoded is such a chat's manifest too.
    let stored = m.as_ref().filter(|m| m.encoded()).map(Manifest::stored_bytes);
    Ok(StageReport { session: sid.to_string(), bytes, parts, key, outcome: "already", view, origin: None, rate: None, stored })
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
        // S11 (C.3.7): an encoded stage names its stored bytes; an identity one prints S10's line.
        let stored = report.stored.map_or_else(String::new, |n| format!(" ({n} stored, {})", PartEncoding::Gzip.word()));
        writeln!(out, "{} {}: {} bytes{stored}, {} part(s), {}{view}{origin}", report.outcome, report.session, report.bytes, report.parts, report.key)?;
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
            "session": report.session, "bytes": report.bytes, "stored": report.stored, "parts": report.parts, "key": report.key, "outcome": report.outcome,
            "view": report.view, "origin": report.origin.as_ref().map(|p| p.display().to_string()), "restore": restore,
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?)?;
    } else if let Some(r) = restored {
        writeln!(out, "{}", r.line(&report.session))?;
    }
    out.flush()?;
    warmed.map(drop)
}

/// The `transcript_stage` audit row of `r`; S10 (F5) with its `rate` (bytes
/// per second) when it uploaded; S11 (C.3.7) with its `stored` bytes when the
/// chat is stored encoded (`bytes` stays the raw bytes, `rate` is the stored
/// bytes').
fn audit_stage(paths: &Paths, r: &StageReport, t0: std::time::Instant) {
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut pairs = vec![("session", r.session.clone()), ("bytes", r.bytes.to_string()), ("parts", r.parts.to_string()), ("outcome", r.outcome.to_string()), ("ms", ms.to_string())];
    if let Some(rate) = r.rate {
        pairs.push(("rate", rate.to_string()));
    }
    if let Some(stored) = r.stored {
        pairs.push(("stored", stored.to_string()));
    }
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
/// (`report_and_warm`). S10 (F3a): `--warm` with
/// `[vm].reuse_per_workspace` off is refused right after bridge.toml is
/// read, before anything is staged and before any Touch ID
/// ([`refuse_warm_without_reuse`]).
/// Exits: 0 staged, resumed or already (and with `--warm` warmed and
/// restored); 9 a finding (nothing sent), or a chat whose recorded cwd is
/// outside the roots or in no git repository (it could never reopen once
/// staged: [`chat_workspace`], with `--warm` or without), or `--warm` with
/// `[vm].reuse_per_workspace` off; 1 no such chat, one begun on a VM
/// (without `--warm`), or an S8 mirror (`session migrate-s9` takes it), one
/// whose cwd is unknown, gone or an unsupported repository, an original
/// that is not the copy S3 holds; 2 usage; 5 no runtime key; 7 S3; the
/// warm's own.
pub fn cmd_stage(store: &Keystore, uuid: &str, warm: bool, json: bool) -> crate::errors::Result<()> {
    use crate::bridge::vm::cmd::{backend, runtime, Backend, Ctx};
    use std::os::fd::AsFd as _;
    if !crate::bridge::registry::is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let ctx = Ctx::load()?;
    if warm {
        refuse_warm_without_reuse(&ctx.cfg, uuid)?;
    }
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
    let warm = workspace.map(|workspace| move || crate::bridge::vm::cmd::main_with(store, crate::cli::VmCmd::Warm { workspace, json: false, dry_run: false, prewarm: false, claude_version: None }, Some(chat)));
    report_and_warm(&report, json, &mut std::io::stdout(), std::io::stderr().as_fd(), warm)
}

/// S10 (F3a): `session stage --warm` warms the workspace's VM so that the
/// chat's reopen reuses it with the chat restored there; with
/// `[vm].reuse_per_workspace` off no reopen reuses a VM, so the warm would
/// cost Touch IDs and a VM for nothing. Refused then (`Policy`, exit 9),
/// naming the switch, before anything is staged or asked.
pub fn refuse_warm_without_reuse(cfg: &BridgeConfig, uuid: &str) -> crate::errors::Result<()> {
    if cfg.vm.reuse_per_workspace {
        return Ok(());
    }
    Err(CliError::Policy(format!(
        "session stage --warm: [vm] reuse_per_workspace is off, so the chat's reopen would reuse no VM and never the one --warm warms: set it to true in bridge.toml, then run ai-env session stage {uuid} --warm again (nothing was staged or warmed)"
    )))
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
        let report = StageReport { session: SID.into(), bytes: 600, parts: 1, key: format!("v1/{SID}/mac/{}", "a".repeat(64)), outcome: "staged", view: Some(format!("-w/{SID}.jsonl")), origin: Some(PathBuf::from("/s/origin")), rate: Some(1_000_000), stored: None };
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

#[cfg(test)]
mod s11_tests {
    use super::*;

    /// S11 (C.3.5): `session stage` takes at most 16 GiB in all and 4 GiB a file, both decoded: a sparse file of
    /// 4 GiB + 1 is refused whatever the cap (naming its own bytes), as is a sum past 16 GiB; both caps exactly
    /// pass. The subtree goes `MULTIPART_PARALLEL` at a time.
    #[test]
    fn the_stage_caps_each_file_and_the_sum() {
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        assert_eq!((STAGE_MAX, STAGE_FILE_MAX, SUBTREE_PARALLEL), (16 << 30, 4 << 30, MULTIPART_PARALLEL));
        assert_eq!(STAGE_FILE_MAX, crate::wire::workspace::PULL_MAX);
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("-w");
        std::fs::create_dir_all(dir.join(SID)).unwrap();
        let sparse = |path: &Path, len: u64| std::fs::File::create(path).unwrap().set_len(len).unwrap();
        let main = dir.join(format!("{SID}.jsonl"));
        sparse(&main, STAGE_FILE_MAX + 1);
        let too_large = |r: Result<Option<MacChat>, BridgeError>| match r {
            Err(BridgeError::TranscriptTooLarge { session, bytes }) => (session, bytes),
            other => panic!("{other:?}"),
        };
        assert_eq!(too_large(locate(tmp.path(), &["-w"], SID, STAGE_MAX)), (SID.to_string(), STAGE_FILE_MAX + 1), "a file over 4 GiB");
        assert_eq!(too_large(locate(tmp.path(), &["-w"], SID, u64::MAX)), (SID.to_string(), STAGE_FILE_MAX + 1), "whatever the cap");
        sparse(&main, STAGE_FILE_MAX);
        for i in 0..3 {
            sparse(&dir.join(SID).join(format!("agent-{i}.jsonl")), STAGE_FILE_MAX);
        }
        let chat = locate(tmp.path(), &["-w"], SID, STAGE_MAX).unwrap().expect("both caps exactly");
        assert_eq!((chat.files.len(), chat.bytes()), (4, STAGE_MAX));
        sparse(&dir.join(SID).join("agent-3.jsonl"), 1);
        assert_eq!(too_large(locate(tmp.path(), &["-w"], SID, STAGE_MAX)), (SID.to_string(), STAGE_MAX + 1), "over 16 GiB in all");
    }

    /// S11 (C.3.4): a file's spool is `/usr/bin/gzip -n -6` of exactly the
    /// bytes the scan read (`gzip -dc` gives them back), 0600 in a 0700
    /// directory, named by the file's index; its digest is its own (its
    /// sha256, its parts'). Made again it is the same bytes (the same key),
    /// a leftover of its name replaced; it goes once dropped. Bytes that are
    /// not the scan's (another byte, or fewer) are `changed` (exit 1), the
    /// spool gone.
    #[test]
    fn a_spool_is_gzip_of_the_scanned_bytes_and_made_again_alike() {
        use sha2::{Digest, Sha256};
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let file = tmp.path().join("agent-a1.jsonl");
        let bytes: Vec<u8> = (0..20_000u32).flat_map(|i| format!("{{\"n\":{i},\"text\":\"line {}\"}}\n", i * 7919 % 10_007).into_bytes()).collect();
        std::fs::write(&file, &bytes).unwrap();
        let sha = hex::encode(Sha256::digest(&bytes));
        let len = bytes.len() as u64;
        let (spool, d) = spool_file(&paths, SID, 3, &file, "agent-a1.jsonl", len, &sha, 1000).unwrap();
        assert_eq!(spool.path, paths.transcript_spool(SID).join("3.gz"));
        let stored = std::fs::read(&spool.path).unwrap();
        assert_eq!((d.len, d.sha256.clone(), d.parts.len()), (stored.len() as u64, hex::encode(Sha256::digest(&stored)), stored.len().div_ceil(1000)));
        assert_eq!(d.parts[0], hex::encode(Sha256::digest(&stored[..1000])));
        assert!(d.len < len / 2, "a JSONL file compresses: {} of {len}", d.len);
        assert_eq!(std::fs::metadata(&spool.path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(paths.transcript_spool(SID)).unwrap().permissions().mode() & 0o777, 0o700);
        let mut gunzip = std::process::Command::new(GZIP).arg("-dc").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        gunzip.stdin.take().unwrap().write_all(&stored).unwrap();
        assert_eq!(gunzip.wait_with_output().unwrap().stdout, bytes, "gzip -dc gives the scanned bytes back");
        let at = spool.path.clone();
        drop(spool);
        assert!(!at.exists(), "dropped, the spool goes");
        // A leftover of its name (a cut run's) is never trusted: replaced by the same bytes.
        std::fs::write(&at, b"a cut run's spool").unwrap();
        let (again, d2) = spool_file(&paths, SID, 3, &file, "agent-a1.jsonl", len, &sha, 1000).unwrap();
        assert_eq!((d2.sha256.as_str(), std::fs::read(&again.path).unwrap()), (d.sha256.as_str(), stored), "deterministic: the same key");
        drop(again);
        // A spool whose path another run took over: its drop leaves that run's file, and its digest is its own.
        let (third, d3) = spool_file(&paths, SID, 3, &file, "agent-a1.jsonl", len, &sha, 1000).unwrap();
        assert!(third.intact());
        std::fs::remove_file(&at).unwrap();
        std::fs::write(&at, b"another run's spool").unwrap();
        assert!(!third.intact());
        drop(third);
        assert_eq!((std::fs::read(&at).unwrap(), d3.sha256), (b"another run's spool".to_vec(), d.sha256.clone()), "left to its run");
        std::fs::remove_file(&at).unwrap();
        // The file changed since the scan: one byte, then a shorter file, then a longer one (a turn appended: its
        // first `len` bytes are still the scan's, GZ-1).
        let mut other = bytes.clone();
        other[10] ^= 1;
        let appended = [bytes.as_slice(), b"{\"n\":\"a turn appended\"}\n"].concat();
        for changed in [other, bytes[..bytes.len() - 1].to_vec(), appended] {
            std::fs::write(&file, &changed).unwrap();
            let e = spool_file(&paths, SID, 3, &file, "agent-a1.jsonl", len, &sha, 1000).map(|(_, d)| d).unwrap_err();
            assert_eq!(e.to_string(), format!("workspace failed (changed): the chat changed while it was staged: agent-a1.jsonl is not the bytes the scan read; nothing of it was sent (ai-env session stage {SID} again once the chat is closed)"));
            assert_eq!(crate::errors::CliError::from(e).exit_code(), 1);
            assert!(!at.exists(), "no spool left");
        }
    }

    /// GZ-1: before a view replaces a chat that went up, the chat must still be
    /// the bytes the scan read. A turn appended to the main or to a subtree
    /// file, a new subtree file, or a main of its length with other bytes is
    /// refused (exit 1) naming the purge and the stage again; the files stay.
    #[test]
    fn a_chat_that_went_on_while_it_was_staged_is_refused_before_its_view() {
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("-w");
        std::fs::create_dir_all(dir.join(SID).join("subagents")).unwrap();
        let main = dir.join(format!("{SID}.jsonl"));
        let sub = dir.join(SID).join("subagents").join("agent-a1.jsonl");
        let (main_bytes, sub_bytes) = (b"{\"turn\":0}\n{\"turn\":1}\n".to_vec(), b"{\"sub\":0}\n".to_vec());
        let reset = || {
            std::fs::write(&main, &main_bytes).unwrap();
            std::fs::write(&sub, &sub_bytes).unwrap();
            let _ = std::fs::remove_file(dir.join(SID).join("subagents").join("agent-a2.jsonl"));
        };
        reset();
        let chat = locate(tmp.path(), &["-w"], SID, STAGE_MAX).unwrap().unwrap();
        let digests = scan_chat(&Rules::defaults(), &chat, MULTIPART_PART).unwrap();
        unchanged_since_scan(&chat, &digests, SID).unwrap();
        let refused = format!(
            "{} is not the copy S3 holds of {SID} (the chat went on here while it was staged): it stays where it is; ai-env session forget {SID} --purge, then ai-env session stage {SID}, stages it with every local turn",
            main.display()
        );
        let append = |p: &Path, line: &[u8]| {
            use std::io::Write as _;
            std::fs::OpenOptions::new().append(true).open(p).unwrap().write_all(line).unwrap();
        };
        let cases: [(&str, &dyn Fn()); 4] = [
            ("a turn appended to the main", &|| append(&main, b"{\"turn\":2}\n")),
            ("a subtree file appended to", &|| append(&sub, b"{\"sub\":1}\n")),
            ("a new subtree file", &|| std::fs::write(dir.join(SID).join("subagents").join("agent-a2.jsonl"), b"{}\n").unwrap()),
            ("the main's length, other bytes", &|| std::fs::write(&main, b"{\"turn\":0}\n{\"turn\":9}\n").unwrap()),
        ];
        for (what, change) in cases {
            reset();
            change();
            let e = unchanged_since_scan(&chat, &digests, SID).expect_err(what);
            assert_eq!(e.to_string(), format!("config: {refused}"), "{what}");
            assert_eq!(crate::errors::CliError::from(e).exit_code(), 1, "{what}");
            assert!(main.exists() && sub.exists(), "{what}: the files stay");
        }
        reset();
        unchanged_since_scan(&chat, &digests, SID).unwrap();
    }

    /// S11 (C.3.7): an encoded stage's line names its stored bytes after its
    /// bytes (`(<stored> stored, gzip)`) and its `--json` document `stored`;
    /// an identity one prints S10's line, `stored` null.
    #[test]
    fn the_report_names_its_stored_bytes() {
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        use std::os::fd::AsFd as _;
        let key = format!("v1/{SID}/mac/{}", "a".repeat(64));
        let report = StageReport { session: SID.into(), bytes: 600, parts: 1, key: key.clone(), outcome: "staged", view: None, origin: None, rate: Some(1_000_000), stored: Some(123) };
        let err = tempfile::tempfile().unwrap();
        let none = None::<fn() -> crate::errors::Result<Option<WarmRestore>>>;
        let mut out = Vec::new();
        report_and_warm(&report, false, &mut out, err.as_fd(), none).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("staged {SID}: 600 bytes (123 stored, gzip), 1 part(s), {key}\n"));
        let mut out = Vec::new();
        report_and_warm(&report, true, &mut out, err.as_fd(), none).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!((doc["bytes"].as_u64(), doc["stored"].as_u64()), (Some(600), Some(123)), "{doc}");
        let identity = StageReport { stored: None, ..report };
        let mut out = Vec::new();
        report_and_warm(&identity, false, &mut out, err.as_fd(), none).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("staged {SID}: 600 bytes, 1 part(s), {key}\n"), "S10's line");
        let mut out = Vec::new();
        report_and_warm(&identity, true, &mut out, err.as_fd(), none).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(doc["stored"].is_null() && doc.get("stored").is_some(), "{doc}");
    }
}

#[cfg(test)]
mod s10_tests {
    use super::*;

    /// F5: a stage's pace is below `dataplane::MIN_RATE` once its bytes
    /// took longer than at 1 MB/s by more than the slack a few requests'
    /// latency take: never for nothing sent, nor for a small chat a slow
    /// round trip holds up; the 1.87 GB chat at S9's 0.6 MB/s is. The rate
    /// is its bytes per second, shown in kB/s from 10 kB/s.
    #[test]
    fn the_pace_is_below_min_rate_past_the_slack() {
        assert!(!below_min_rate(0, 60_000), "nothing sent");
        assert!(!below_min_rate(100_000, 1_900), "a small chat, a slow round trip");
        assert!(below_min_rate(100_000, 2_200));
        assert!(!below_min_rate(1_000_000, 3_000) && below_min_rate(1_000_000, 3_001), "1 MB at the rate, then the slack");
        assert!(below_min_rate(1_870_000_000, 1_870_000_000 / 600), "the dev chat at 0.6 MB/s");
        assert!(!below_min_rate(1_870_000_000, 1_870_000_000 / 1_100), "at 1.1 MB/s");
        assert_eq!((rate_of(600_000, 1_000), rate_of(5, 0), rate_of(u64::MAX, 1)), (600_000, 5_000, u64::MAX), "saturating");
        assert_eq!((shown_rate(640), shown_rate(9_999), shown_rate(10_000), shown_rate(612_345)), ("640 B/s".to_string(), "9999 B/s".to_string(), "10 kB/s".to_string(), "612 kB/s".to_string()));
    }

    /// F3a: `--warm` is refused with `[vm].reuse_per_workspace` off (exit 9,
    /// naming the switch and the command to run again), never with it on.
    #[test]
    fn warm_without_reuse_is_refused_naming_the_switch() {
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        assert!(refuse_warm_without_reuse(&BridgeConfig::default(), SID).is_ok(), "reuse is on by default");
        let off = BridgeConfig::parse("[vm]\nreuse_per_workspace = false\n").unwrap();
        let e = refuse_warm_without_reuse(&off, SID).unwrap_err();
        assert_eq!(e.exit_code(), 9);
        assert_eq!(e.to_string(), format!("session stage --warm: [vm] reuse_per_workspace is off, so the chat's reopen would reuse no VM and never the one --warm warms: set it to true in bridge.toml, then run ai-env session stage {SID} --warm again (nothing was staged or warmed)"));
    }
}
