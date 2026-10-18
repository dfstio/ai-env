//! A session's manifest of what S3 holds (S9 plan §5, G4):
//! `state/transcripts/<sid>/manifest.toml` (0600, written atomically, under
//! `Paths::transcript_lock`). The Mac signed every write, so it never reads
//! an object: the manifest lists each part (in order: the transcript is their
//! concatenation), its version, offset, length and sha256, the subtree's
//! files by rel, the committed length and its fingerprint, the VM file's
//! inode, and the keys a compaction replaced. It can be rebuilt from a
//! ListObjectsV2 of `v1/<sid>/` (the keys encode the offsets). Phase 0
//! declares its serde types and [`origin_of`]'s stub; G4 reads and writes it.
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use serde::{Deserialize, Serialize};

/// The manifest's version.
pub const MANIFEST_V: u32 = 1;

/// `manifest.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// [`MANIFEST_V`].
    pub v: u32,
    pub session: String,
    pub bucket: String,
    pub owner: String,
    /// `"vm"` or `"mac"`: where the chat began.
    pub origin: String,
    /// The transcript's rel under the projects directory (`<slug>/<sid>.jsonl`).
    pub rel: String,
    /// The VM generation of the parts (0: a Mac object only).
    pub gen: u32,
    /// The bytes S3 holds: the parts' sum.
    pub committed: u64,
    /// The stat's `end_fp` at `committed` (lowercase hex sha256 of the `FP_SPAN` bytes before it).
    pub fp: String,
    /// The VM file's inode at the last commit (none before a VM held it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
    /// The VM of the last commit (none before a VM held it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
    /// When it was last written (RFC 3339 UTC).
    pub at: String,
    /// Keys a compaction replaced, deleted at the next sync.
    #[serde(default)]
    pub superseded: Vec<String>,
    #[serde(default)]
    pub parts: Vec<ManifestPart>,
    /// The `<sid>/` subtree, by rel.
    #[serde(default)]
    pub files: Vec<ManifestFile>,
}

/// One part of the transcript in S3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPart {
    pub key: String,
    /// Always a 200's.
    pub version_id: String,
    pub from: u64,
    pub len: u64,
    pub sha256: String,
}

/// One file of the session's subtree in S3 (`v1/<sid>/vm/f/<sha256>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub rel: String,
    pub key: String,
    /// Unknown when a push answered 412 and no other entry holds that key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    pub len: u64,
    pub sha256: String,
}

/// Where a chat began, the one predicate P0, P3, `session stage`,
/// `migrate-s9` and `fill_remote` use: with a manifest, its `origin` (`"vm"`
/// or `"mac"`); without one, the registry row: `transcript_home = "s3"` is
/// `"vm"`, `mode = "remote"` without it `"s8_mirror"` (never written to a
/// row); else `None`, a chat begun on this Mac when it has a local
/// transcript. A local file `wire::view::is_view_head` takes is never a Mac
/// copy. A manifest that cannot be read counts as none (the row decides);
/// the row's own `origin` field is this function's output, never its input.
#[must_use]
pub fn origin_of(paths: &Paths, sid: &str) -> Option<&'static str> {
    if !crate::bridge::registry::is_uuid(sid) {
        return None;
    }
    if let Ok(Some(m)) = read(paths, sid) {
        match m.origin.as_str() {
            ORIGIN_VM => return Some(ORIGIN_VM),
            ORIGIN_MAC => return Some(ORIGIN_MAC),
            _ => {}
        }
    }
    let row = crate::bridge::registry::read(paths, sid).ok().flatten()?;
    if row.transcript_home.as_deref() == Some(HOME_S3) {
        return Some(ORIGIN_VM);
    }
    (row.mode == "remote").then_some(ORIGIN_S8_MIRROR)
}

// ---- the manifest on disk (G4) -----------------------------------------------------------------

/// A chat begun on a VM.
pub const ORIGIN_VM: &str = "vm";
/// A chat begun on this Mac (its first part a `v1/<sid>/mac/<sha256>` object).
pub const ORIGIN_MAC: &str = "mac";
/// [`origin_of`]'s word for an S8 remote chat whose Mac copy is the mirror (never written to a row or a manifest).
pub const ORIGIN_S8_MIRROR: &str = "s8_mirror";
/// `SessionRow::transcript_home` of a session whose transcript is kept in S3.
pub const HOME_S3: &str = "s3";
/// How long a writer waits for a session's manifest lock.
pub const LOCK_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// The manifest of `sid` (a uuid `registry::is_uuid` took): `Ok(None)` when
/// it does not exist; a symlink, a non-regular file, TOML that does not
/// parse, another version or another session is an error naming the file.
pub fn read(paths: &Paths, sid: &str) -> Result<Option<Manifest>, BridgeError> {
    let path = paths.transcript_manifest(sid);
    let Some(text) = crate::bridge::registry::read_regular_file(&path)? else {
        return Ok(None);
    };
    let m: Manifest = toml::from_str(&text).map_err(|e| BridgeError::Config(format!("{}: {}", path.display(), e.message())))?;
    if m.v != MANIFEST_V || m.session != sid {
        return Err(BridgeError::Config(format!("{}: manifest v{} of session {} (this ai-env reads v{MANIFEST_V} of {sid})", path.display(), m.v, m.session)));
    }
    Ok(Some(m))
}

/// Write `m` atomically (a 0600 temp file beside it, fsync, rename; never
/// through a symlink), `state/transcripts/<sid>/` made a real 0700 directory
/// first. The caller holds [`lock`].
pub fn write(paths: &Paths, m: &Manifest) -> Result<(), BridgeError> {
    if !crate::bridge::registry::is_uuid(&m.session) {
        return Err(BridgeError::Config(format!("manifest: not a session id: {:?}", m.session)));
    }
    let dir = paths.transcript_dir(&m.session);
    crate::bridge::registry::ensure_private_dir(&dir)?;
    let text = toml::to_string(m).map_err(|e| BridgeError::Config(format!("manifest of {}: {e}", m.session)))?;
    let body = format!("# Written by ai-env: what the transcripts bucket holds of this session (never a transcript byte).\n{text}");
    crate::bridge::infra::write_atomic_mode(&paths.transcript_manifest(&m.session), body.as_bytes(), 0o600)
}

/// The session's manifest lock (`state/transcripts/<sid>.lock`, flock): one
/// writer of the manifest at a time, waited for at most [`LOCK_BUDGET`].
pub async fn lock(paths: &Paths, sid: &str) -> Result<crate::bridge::vm::lock::FlockGuard, BridgeError> {
    if !crate::bridge::registry::is_uuid(sid) {
        return Err(BridgeError::Config(format!("manifest: not a session id: {sid:?}")));
    }
    crate::bridge::vm::lock::lock_exclusive(&paths.transcript_lock(sid), LOCK_BUDGET, &format!("the transcript manifest of {sid}")).await
}

impl Manifest {
    /// An empty manifest of `session` in `target`'s bucket, begun at `origin`, for `rel`.
    #[must_use]
    pub fn new(session: &str, target: &super::S3Target, origin: &str, rel: &str, at: &str) -> Manifest {
        Manifest {
            v: MANIFEST_V,
            session: session.to_string(),
            bucket: target.bucket.clone(),
            owner: target.owner.clone(),
            origin: origin.to_string(),
            rel: rel.to_string(),
            gen: 0,
            committed: 0,
            fp: String::new(),
            ino: None,
            vm: None,
            at: at.to_string(),
            superseded: Vec::new(),
            parts: Vec::new(),
            files: Vec::new(),
        }
    }

    /// The bytes of the first part: the generation's base, or a Mac-begun chat's object.
    #[must_use]
    pub fn base_len(&self) -> u64 {
        self.parts.first().map_or(0, |p| p.len)
    }

    /// The parts after the first (the segments appended since the base), and their bytes.
    #[must_use]
    pub fn segments(&self) -> (usize, u64) {
        let segs = self.parts.iter().skip(1);
        (segs.clone().count(), segs.map(|p| p.len).sum())
    }

    /// Whether appending a segment of `len` bytes is due a compaction instead
    /// (a full copy as the next generation's base): the segments would number
    /// `COMPACT_SEGMENTS`, or their bytes pass max(`COMPACT_BYTES_MIN`, base / 2).
    #[must_use]
    pub fn compaction_due(&self, len: u64) -> bool {
        let (n, bytes) = self.segments();
        n + 1 >= crate::wire::s3::COMPACT_SEGMENTS || bytes.saturating_add(len) > crate::wire::s3::COMPACT_BYTES_MIN.max(self.base_len() / 2)
    }

    /// A segment pushed at `committed` stored as `part` (in generation
    /// `max(gen, 1)`: a Mac-begun chat's first VM bytes open generation 1):
    /// appended; `committed`, `fp`, `ino`, `vm` and `at` follow.
    pub fn commit_segment(&mut self, part: ManifestPart, fp: &str, ino: Option<u64>, vm: &str, at: &str) {
        self.gen = self.gen.max(1);
        self.committed = part.from + part.len;
        self.parts.push(part);
        self.follow(fp, ino, vm, at);
    }

    /// A full copy stored as `part`, generation `gen`'s base: it replaces
    /// every part, whose keys go to `superseded` (deleted at the next sync).
    pub fn commit_base(&mut self, gen: u32, part: ManifestPart, fp: &str, ino: Option<u64>, vm: &str, at: &str) {
        for old in std::mem::take(&mut self.parts) {
            if old.key != part.key && !self.superseded.contains(&old.key) {
                self.superseded.push(old.key);
            }
        }
        self.gen = gen;
        self.committed = part.len;
        self.parts.push(part);
        self.follow(fp, ino, vm, at);
    }

    fn follow(&mut self, fp: &str, ino: Option<u64>, vm: &str, at: &str) {
        self.fp = fp.to_string();
        self.ino = ino;
        self.vm = Some(vm.to_string());
        self.at = at.to_string();
    }

    /// The version a `[[files]]` entry may take for `key`: another entry's that holds it (a 412 on a key named by its
    /// bytes' sha256 leaves the version to whichever earlier push stored it).
    #[must_use]
    pub fn file_version(&self, key: &str) -> Option<String> {
        self.files.iter().find(|f| f.key == key).and_then(|f| f.version_id.clone())
    }
}

/// What the next sync pushes of the VM's transcript ([`plan_push`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushPlan {
    /// The VM holds no transcript at the rel: nothing to push.
    Absent,
    /// S3 holds the VM's bytes already.
    UpToDate,
    /// Append `[from, from + len)` as generation `gen`'s segment at `from`.
    Segment { gen: u32, from: u64, len: u64 },
    /// A full copy, `len` bytes, as generation `gen`'s base; `why`: `first`,
    /// `shrank`, `inode`, `fingerprint` or `compaction`.
    Base { gen: u32, len: u64, why: &'static str },
}

/// The push a sync makes (plans/s9-contracts.md §5.8): nothing when the VM
/// holds no file or S3 holds its bytes; else a segment of what was appended
/// past `committed`, unless the VM's file was rewritten — it shrank, its
/// inode changed on the VM that committed last (`vm`), or the bytes before
/// `committed` no longer hash to `fp` (`fp_ok` false) — or a compaction is
/// due ([`Manifest::compaction_due`]): then a full copy as the next
/// generation's base. Without a manifest (or nothing committed yet) the
/// first push is generation 1's base.
#[must_use]
pub fn plan_push(m: Option<&Manifest>, stat: &crate::wire::workspace::TranscriptStat, vm: &str) -> PushPlan {
    if !stat.present {
        return PushPlan::Absent;
    }
    let Some(m) = m.filter(|m| m.committed > 0) else {
        let gen = m.map_or(0, |m| m.gen) + 1;
        return if stat.size == 0 { PushPlan::UpToDate } else { PushPlan::Base { gen, len: stat.size, why: "first" } };
    };
    let next = PushPlan::Base { gen: m.gen + 1, len: stat.size, why: "" };
    let base = |why: &'static str| match next {
        PushPlan::Base { gen, len, .. } => PushPlan::Base { gen, len, why },
        _ => unreachable!("next is a base"),
    };
    if stat.size < m.committed {
        return base("shrank");
    }
    if m.vm.as_deref() == Some(vm) && m.ino.is_some() && stat.ino.is_some() && m.ino != stat.ino {
        return base("inode");
    }
    if stat.fp_ok != Some(true) {
        return base("fingerprint");
    }
    if stat.size == m.committed {
        return PushPlan::UpToDate;
    }
    let len = stat.size - m.committed;
    if m.compaction_due(len) {
        return base("compaction");
    }
    PushPlan::Segment { gen: m.gen.max(1), from: m.committed, len }
}

/// The sha256 (lowercase hex) of the last `FP_SPAN` bytes of `bytes`: the
/// fingerprint a commit of `bytes.len()` records.
#[must_use]
pub fn fp_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let span = usize::try_from(crate::wire::s3::FP_SPAN).unwrap_or(usize::MAX);
    hex::encode(Sha256::digest(&bytes[bytes.len().saturating_sub(span)..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// plans/s9-contracts.md §5.8's sample: it reads, and it writes back as it read.
    #[test]
    fn the_sample_manifest_reads_and_round_trips() {
        let text = r#"v = 1
session = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
bucket = "ai-env-transcripts-123456789012"
owner = "123456789012"
origin = "vm"
rel = "-Users-mike-Documents-DeFi-ai-env/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl"
gen = 1
committed = 52000
fp = "756ad326b9d0e363b1359566e1992e0bcdaa19c4939f0c7ad890dcfea3f9fd4a"
ino = 1234567
vm = "microvm-0123456789abcdef"
at = "2026-10-17T10:15:30.123Z"
superseded = []

[[parts]]
key = "v1/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/vm/g1/base"
version_id = "fv1"
from = 0
len = 48213
sha256 = "841075eede78b44b2d2862f4c38a643daf938671983e4ca0563a98a82ceddcd1"

[[parts]]
key = "v1/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/vm/g1/s/000000000000bc55"
version_id = "fv2"
from = 48213
len = 3787
sha256 = "b094ab054161cac4f8714d6855dc32bf0488f8eed1c4790aec8f054577f7c5c2"

[[files]]
rel = "-Users-mike-Documents-DeFi-ai-env/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/subagents/agent-a1.jsonl"
key = "v1/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/vm/f/d569b20cbdd570395fd77fa48b21cf76be5842248a2b7571ea17204e6b907e59"
version_id = "fv3"
len = 4096
sha256 = "d569b20cbdd570395fd77fa48b21cf76be5842248a2b7571ea17204e6b907e59"
"#;
        let m: Manifest = toml::from_str(text).unwrap();
        assert_eq!((m.v, m.gen, m.committed, m.parts.len(), m.files.len()), (MANIFEST_V, 1, 52000, 2, 1));
        assert_eq!(m.parts.iter().map(|p| p.len).sum::<u64>(), m.committed, "the parts' sum");
        for p in &m.parts {
            assert!(crate::wire::s3::S3Key::parse(&p.key).is_some(), "{}", p.key);
        }
        assert_eq!(toml::from_str::<Manifest>(&toml::to_string(&m).unwrap()).unwrap(), m);
        assert!(toml::from_str::<Manifest>(&text.replace("gen = 1", "gen = 1\nextra = 2")).is_err(), "unknown keys are refused");
        let mac_only = Manifest { origin: "mac".into(), gen: 0, ino: None, vm: None, files: Vec::new(), ..m };
        let written = toml::to_string(&mac_only).unwrap();
        assert!(!written.contains("ino") && !written.contains("vm ="), "{written}");
        assert_eq!(origin_of(&Paths::from_root_and_env("/nonexistent/bridge".into(), None), "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"), None, "phase 0's stub");
    }
}

#[cfg(test)]
mod g4_tests {
    use super::*;
    use crate::bridge::s3::{S3Endpoint, S3Target, LAB_BUCKET, LAB_OWNER};
    use crate::wire::s3::{S3Key, COMPACT_BYTES_MIN, COMPACT_SEGMENTS};
    use crate::wire::workspace::TranscriptStat;

    const S: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const VM: &str = "microvm-0123456789abcdef";

    fn target() -> S3Target {
        S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Aws }
    }

    /// The VM's stat of a file of `size` bytes, inode `ino`, whose prefix matches the manifest's fingerprint (`fp_ok`).
    fn stat(size: u64, ino: u64, fp_ok: bool) -> TranscriptStat {
        TranscriptStat { present: true, size, ino: Some(ino), fp_ok: Some(fp_ok), end_fp: Some(format!("{size:064x}")), ..TranscriptStat::default() }
    }

    fn part(key: S3Key, from: u64, len: u64) -> ManifestPart {
        ManifestPart { key: key.render(), version_id: format!("fv{from}"), from, len, sha256: "a".repeat(64) }
    }

    /// The first push is generation 1's base; every later turn's bytes are a
    /// segment at the committed length, appended in order, the parts' sum
    /// the committed length; 63 segments stay segments, the push that would
    /// make the 64th is a full copy as generation 2's base, the old keys
    /// superseded; so is a segment whose bytes would pass max(64 MiB, base / 2).
    #[test]
    fn manifest_appends_segments_then_compacts() {
        let mut m = Manifest::new(S, &target(), ORIGIN_VM, &format!("-w/{S}.jsonl"), "2026-10-17T10:15:30.000Z");
        assert_eq!(plan_push(Some(&m), &stat(0, 7, true), VM), PushPlan::UpToDate, "an empty file is nothing to push");
        assert_eq!(plan_push(None, &TranscriptStat::default(), VM), PushPlan::Absent);
        assert_eq!(plan_push(Some(&m), &stat(1000, 7, true), VM), PushPlan::Base { gen: 1, len: 1000, why: "first" });
        m.commit_base(1, part(S3Key::Base { session: S.into(), gen: 1 }, 0, 1000), "f", Some(7), VM, "t1");
        let mut size = 1000;
        for i in 0..COMPACT_SEGMENTS - 1 {
            let plan = plan_push(Some(&m), &stat(size + 10, 7, true), VM);
            assert_eq!(plan, PushPlan::Segment { gen: 1, from: size, len: 10 }, "segment {i}");
            m.commit_segment(part(S3Key::Segment { session: S.into(), gen: 1, offset: size }, size, 10), "f", Some(7), VM, "t");
            size += 10;
            assert_eq!(m.parts.iter().map(|p| p.len).sum::<u64>(), m.committed, "the parts' sum");
        }
        assert_eq!((m.segments().0, m.committed, m.gen), (COMPACT_SEGMENTS - 1, size, 1));
        assert!(m.parts.windows(2).all(|w| w[0].from + w[0].len == w[1].from), "contiguous, in order");
        assert_eq!(plan_push(Some(&m), &stat(size, 7, true), VM), PushPlan::UpToDate);
        let plan = plan_push(Some(&m), &stat(size + 10, 7, true), VM);
        assert_eq!(plan, PushPlan::Base { gen: 2, len: size + 10, why: "compaction" });
        let old: Vec<String> = m.parts.iter().map(|p| p.key.clone()).collect();
        m.commit_base(2, part(S3Key::Base { session: S.into(), gen: 2 }, 0, size + 10), "g", Some(7), VM, "t2");
        assert_eq!((m.parts.len(), m.gen, m.committed, m.superseded.clone()), (1, 2, size + 10, old));
        // By bytes: a 1 KB base takes segments up to 64 MiB in all, then a full copy.
        assert_eq!(plan_push(Some(&m), &stat(m.committed + COMPACT_BYTES_MIN, 7, true), VM), PushPlan::Segment { gen: 2, from: m.committed, len: COMPACT_BYTES_MIN });
        assert!(matches!(plan_push(Some(&m), &stat(m.committed + COMPACT_BYTES_MIN + 1, 7, true), VM), PushPlan::Base { gen: 3, why: "compaction", .. }));
        // A large base raises the bar to half its size.
        let mut big = Manifest::new(S, &target(), ORIGIN_VM, &format!("-w/{S}.jsonl"), "t");
        big.commit_base(1, part(S3Key::Base { session: S.into(), gen: 1 }, 0, 300 << 20), "f", Some(7), VM, "t");
        assert!(matches!(plan_push(Some(&big), &stat((300 << 20) + (100 << 20), 7, true), VM), PushPlan::Segment { .. }), "100 MiB is under 150 MiB");
        assert!(matches!(plan_push(Some(&big), &stat((300 << 20) + (151 << 20), 7, true), VM), PushPlan::Base { why: "compaction", .. }));
        // A Mac-begun chat's first VM bytes open generation 1 after its Mac object.
        let mut mac = Manifest::new(S, &target(), ORIGIN_MAC, &format!("-w/{S}.jsonl"), "t");
        mac.parts.push(part(S3Key::Mac { session: S.into(), sha256: "b".repeat(64) }, 0, 500));
        mac.committed = 500;
        assert_eq!(plan_push(Some(&mac), &stat(600, 9, true), VM), PushPlan::Segment { gen: 1, from: 500, len: 100 });
        mac.commit_segment(part(S3Key::Segment { session: S.into(), gen: 1, offset: 500 }, 500, 100), "f", Some(9), VM, "t");
        assert_eq!((mac.gen, mac.committed, mac.parts.len()), (1, 600, 2));
    }

    /// A rewritten file starts a new generation (a full copy), never a
    /// segment over bytes S3 does not hold: shorter than committed, another
    /// inode on the VM that committed last, or a prefix whose fingerprint
    /// no longer matches; another VM's inode alone decides nothing (a
    /// restore made a new file there), its fingerprint does. The manifest
    /// round-trips through its file under the lock, 0600 in a 0700 directory.
    #[tokio::test]
    async fn rewritten_prefix_starts_a_generation() {
        let mut m = Manifest::new(S, &target(), ORIGIN_VM, &format!("-w/{S}.jsonl"), "t");
        m.commit_base(1, part(S3Key::Base { session: S.into(), gen: 1 }, 0, 1000), "f", Some(7), VM, "t");
        m.commit_segment(part(S3Key::Segment { session: S.into(), gen: 1, offset: 1000 }, 1000, 50), "f", Some(7), VM, "t");
        assert_eq!(plan_push(Some(&m), &stat(900, 7, true), VM), PushPlan::Base { gen: 2, len: 900, why: "shrank" });
        assert_eq!(plan_push(Some(&m), &stat(2000, 8, true), VM), PushPlan::Base { gen: 2, len: 2000, why: "inode" });
        assert_eq!(plan_push(Some(&m), &stat(2000, 7, false), VM), PushPlan::Base { gen: 2, len: 2000, why: "fingerprint" });
        assert_eq!(plan_push(Some(&m), &TranscriptStat { fp_ok: None, ..stat(2000, 7, true) }, VM), PushPlan::Base { gen: 2, len: 2000, why: "fingerprint" }, "an unchecked prefix is no match");
        assert_eq!(plan_push(Some(&m), &stat(2000, 8, true), "microvm-another"), PushPlan::Segment { gen: 1, from: 1050, len: 950 }, "another VM's inode alone");
        assert_eq!(plan_push(Some(&m), &stat(2000, 8, false), "microvm-another"), PushPlan::Base { gen: 2, len: 2000, why: "fingerprint" });
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        assert_eq!(read(&paths, S).unwrap(), None);
        assert_eq!(origin_of(&paths, S), None);
        {
            let _held = lock(&paths, S).await.unwrap();
            write(&paths, &m).unwrap();
        }
        assert_eq!(read(&paths, S).unwrap().as_ref(), Some(&m));
        assert_eq!(origin_of(&paths, S), Some(ORIGIN_VM));
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(paths.transcript_manifest(S)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(paths.transcript_dir(S)).unwrap().permissions().mode() & 0o777, 0o700);
        let text = std::fs::read_to_string(paths.transcript_manifest(S)).unwrap();
        assert!(text.starts_with("# Written by ai-env") && !text.contains("X-Amz"), "{text}");
        // Another session's manifest under this id is refused; so is a non-uuid.
        std::fs::write(paths.transcript_manifest(S), text.replace(S, "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c")).unwrap();
        assert!(read(&paths, S).unwrap_err().to_string().contains("of session 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"));
        assert!(lock(&paths, "../x").await.is_err());
        assert_eq!(fp_of(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /// Without a manifest the registry row decides: `transcript_home = "s3"`
    /// is a VM-begun chat, a remote row without it an S8 mirror's, any other
    /// row none (a chat begun on this Mac).
    #[test]
    fn origin_falls_back_to_the_registry_row() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let row = |mode: &str, home: Option<&str>| crate::bridge::registry::SessionRow { session_id: S.into(), mode: mode.into(), transcript_home: home.map(str::to_string), ..crate::bridge::registry::SessionRow::default() };
        for (r, want) in [(row("remote", Some("s3")), Some(ORIGIN_VM)), (row("remote", None), Some(ORIGIN_S8_MIRROR)), (row("local-child", None), None)] {
            crate::bridge::registry::write(&paths, &r).unwrap();
            assert_eq!(origin_of(&paths, S), want, "{r:?}");
        }
        assert_eq!(origin_of(&paths, "not-a-uuid"), None);
    }
}
