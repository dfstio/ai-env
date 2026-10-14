//! The shallow seed transport (S8 D7): a first seed sends a pack of exactly
//! HEAD's commit and tree plus the WIP commits, behind one JSON manifest
//! line, never the history and never a tag; an update (D3) sends a thin pack
//! of what the VM lacks. Caps from `[seed]` (`wrapper_inline_mib` in the
//! wrapper, `max_mib` from `box seed` and the prewarm). Built in S8 wave 1
//! (W4).
//!
//! What a pack carries is listed first (`rev-list --objects`), so the scans
//! read exactly what `pack-objects` then packs from that list: the scan and
//! the transfer never disagree about an object. An update walks the VM's
//! graph, not the Mac's: both walks run with `git --shallow-file` holding
//! the VM's shallow boundary (the seeded head and every boundary commit an
//! earlier update sent, from the workspace row) and this update's own new
//! boundary (the commits whose parents the VM lacks: a merge of a branch
//! older than the seeded commit), so no edge a thin pack deltas against, and
//! no object it leaves out, is history the VM was never sent.
use super::git_failed;
use super::snapshot::{Scratch, Wip};
use crate::bridge::errors::BridgeError;
use crate::wire::workspace::{head_line, ObjectFormat, SeedManifest, HAVES_MAX};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// One object a pack carries: its id, and the path it was first seen at
/// (none for a commit, the root tree's is empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub id: String,
    pub path: Option<String>,
}

/// What a pack carries, as `rev-list --objects` lists it: the objects
/// (`pack-objects` packs exactly these) and, for a thin pack, the edges
/// (commits the VM holds, whose objects a delta may name without sending
/// them), the revisions both walks start from and the shallow file both
/// walk with (`pack-objects --thin` walks them itself, with those grafts,
/// as `rev-list` did).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectList {
    pub objects: Vec<Listed>,
    pub edges: Vec<String>,
    pub thin: bool,
    pub revs: Vec<String>,
    /// The VM's graph for both walks (`git --shallow-file`): its boundary
    /// and this update's new one.
    pub shallow_file: Option<PathBuf>,
}

impl ObjectList {
    /// The list as `pack-objects` reads it on stdin: for a thin pack the
    /// revisions, one per line; else `<id> <path>` per object (the path only
    /// steers the delta search; one holding a newline is left out).
    fn input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.thin {
            for r in &self.revs {
                out.extend_from_slice(r.as_bytes());
                out.push(b'\n');
            }
            return out;
        }
        for o in &self.objects {
            out.extend_from_slice(o.id.as_bytes());
            if let Some(p) = o.path.as_deref().filter(|p| !p.is_empty() && !p.contains('\n')) {
                out.push(b' ');
                out.extend_from_slice(p.as_bytes());
            }
            out.push(b'\n');
        }
        out
    }

    /// The listed commits' ids.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.objects.iter().map(|o| o.id.clone()).collect()
    }
}

/// `rev-list --objects[-edge]` output as an [`ObjectList`]: an object line
/// is `<id>` or `<id> <path>`; `-<id>` is an edge; a line that starts with
/// no object id continues the previous path (a name holding a newline).
fn parse_listing(out: &[u8], format: ObjectFormat, thin: bool) -> ObjectList {
    let mut list = ObjectList { thin, ..ObjectList::default() };
    let text = String::from_utf8_lossy(out);
    for l in text.split('\n') {
        if l.is_empty() {
            continue;
        }
        if let Some(edge) = l.strip_prefix('-').filter(|e| format.is_id(e)) {
            list.edges.push(edge.to_string());
            continue;
        }
        let (id, path) = match l.split_once(' ') {
            Some((id, path)) => (id, Some(path.to_string())),
            None => (l, None),
        };
        if format.is_id(id) {
            list.objects.push(Listed { id: id.to_string(), path });
        } else if let Some(last) = list.objects.last_mut() {
            let p = last.path.get_or_insert_with(String::new);
            p.push('\n');
            p.push_str(l);
        }
    }
    list
}

/// The commits a seed of `head` checks out: the head, then the WIP's (D2).
fn tips(head: &str, wip: Option<&Wip>) -> Vec<String> {
    let mut out = vec![head.to_string()];
    if let Some(w) = wip {
        out.push(w.commit.clone());
        out.extend(w.index_commit.clone());
    }
    out
}

/// The objects of a first seed (a clone or a replace, D7): exactly `head`'s
/// commit and tree, and the WIP's commits and their trees
/// (`rev-list --objects --no-walk`): no parent, no history, no tag.
pub fn first_seed_objects(scratch: &Scratch, head: &str, wip: Option<&Wip>) -> Result<ObjectList, BridgeError> {
    let mut args = vec!["rev-list".to_string(), "--objects".into(), "--no-walk".into()];
    args.extend(tips(head, wip));
    let out = scratch.git().output(&args).map_err(git_failed("git rev-list of the seed's objects"))?;
    Ok(parse_listing(&out, scratch.format(), false))
}

/// What an update sends ([`update_objects`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub list: ObjectList,
    /// The sent commits whose parents the VM lacks (`SeedManifest::shallow`).
    pub shallow: Vec<String>,
}

/// The objects of an update (D3, D7): what the VM at `tip`, seeded at
/// `seeded` (its last seed's head) and shallow at `boundary`, lacks of
/// `head` and its WIP: `rev-list --objects-edge head [W I] ^tip ^seeded`, a
/// thin pack against the edges, both walks in the VM's graph (`git
/// --shallow-file`). `boundary` is the VM's `.git/shallow` as the Mac sent
/// it (the first seed's head and every update's new boundary: the workspace
/// row's), or, when the row cannot vouch for that, `seeded` and `tip`
/// themselves (`rows::boundary`); the VM holds at least the commits `tip`
/// and `seeded` reach within it. A commit the Mac's whole graph would send
/// whose parent the VM lacks (a merge of a branch older than the seeded
/// commit, whose fork point lies below the boundary) is this update's new
/// boundary: listed shallow in the manifest, and cut in both walks too, so
/// that history never travels and no delta bases on it. More than
/// `HAVES_MAX` new boundary commits: `None`
/// (the VM keeps its state). Both `tip` and `seeded` must be commits the Mac
/// holds (the caller checked). Nothing is left in the scratch repository: a
/// 409 `changed` plans again there from the whole graph.
pub fn update_objects(scratch: &Scratch, head: &str, wip: Option<&Wip>, tip: &str, seeded: &str, boundary: &[String]) -> Result<Option<UpdatePlan>, BridgeError> {
    let git = scratch.git();
    let format = scratch.format();
    let positive = tips(head, wip);
    let negative = [format!("^{tip}"), format!("^{seeded}")];
    let ids = |out: &[u8]| -> BTreeSet<String> { String::from_utf8_lossy(out).lines().filter(|l| format.is_id(l)).map(str::to_string).collect() };
    // What the Mac's whole graph would send: the commits neither `tip` nor `seeded` reaches there.
    let mut args = vec!["rev-list".to_string(), "--parents".into()];
    args.extend(positive.iter().cloned());
    args.extend(negative.iter().cloned());
    let parents_out = git.output(&args).map_err(git_failed("git rev-list of the update's commits"))?;
    let mut sent: Vec<(String, Vec<String>)> = Vec::new();
    for l in String::from_utf8_lossy(&parents_out).lines() {
        let mut ids = l.split(' ').filter(|s| format.is_id(s)).map(str::to_string);
        if let Some(c) = ids.next() {
            sent.push((c, ids.collect()));
        }
    }
    let sent_set: BTreeSet<&str> = sent.iter().map(|(c, _)| c.as_str()).collect();
    // What the VM holds: the commits `tip` and `seeded` reach in its graph.
    let vm_graph = shallow_file(scratch, "vm.shallow", boundary.iter())?;
    let held = ids(&git.output([OsStr::new("--shallow-file"), vm_graph.as_os_str(), "rev-list".as_ref(), tip.as_ref(), seeded.as_ref()]).map_err(git_failed("git rev-list of the VM's commits"))?);
    let shallow: Vec<String> = sent
        .iter()
        .filter(|(_, parents)| parents.iter().any(|p| !sent_set.contains(p.as_str()) && !held.contains(p)))
        .map(|(c, _)| c.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if shallow.len() > HAVES_MAX {
        return Ok(None);
    }
    let walk = shallow_file(scratch, "update.shallow", boundary.iter().chain(&shallow))?;
    let mut revs = positive;
    revs.extend(negative);
    let mut args: Vec<OsString> = vec!["--shallow-file".into(), walk.clone().into_os_string(), "rev-list".into(), "--objects-edge".into()];
    args.extend(revs.iter().map(OsString::from));
    let out = git.output(&args).map_err(git_failed("git rev-list of the update's objects"))?;
    let mut list = parse_listing(&out, format, true);
    list.revs = revs;
    list.shallow_file = Some(walk);
    Ok(Some(UpdatePlan { list, shallow }))
}

/// `<scratch>/<name>`, a shallow file of `commits` (one id a line, each once,
/// sorted) for `git --shallow-file`: a graph cut at them.
fn shallow_file<'a>(scratch: &Scratch, name: &str, commits: impl Iterator<Item = &'a String>) -> Result<PathBuf, BridgeError> {
    let commits: BTreeSet<&String> = commits.collect();
    let text: String = commits.into_iter().map(|c| format!("{c}\n")).collect();
    let path = scratch.dir().join(name);
    std::fs::write(&path, text)?;
    Ok(path)
}

/// A `PUT /seed` body, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedBody {
    /// `<scratch>/seed.body` (0600): the manifest line, then the pack.
    pub path: PathBuf,
    /// Its bytes (the request's `Content-Length`).
    pub len: u64,
    pub manifest: SeedManifest,
    /// The objects the pack holds.
    pub objects: u64,
}

/// Write `manifest`'s line, then the pack of `list` (`pack-objects --stdout`,
/// `--thin` for an update), into `<scratch>/seed.body` (0600): `None` when
/// the body would pass `max` bytes (the pack is abandoned and the file
/// removed: the caller names the cap).
pub fn write_body(scratch: &Scratch, manifest: &SeedManifest, list: &ObjectList, max: u64) -> Result<Option<SeedBody>, BridgeError> {
    let path = scratch.dir().join("seed.body");
    let _ = std::fs::remove_file(&path);
    let head = head_line(manifest).map_err(|e| BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::BAD_REQUEST, message: format!("the seed's manifest: {e}") })?;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&path)?;
    file.write_all(&head)?;
    let room = max.saturating_sub(head.len() as u64);
    let mut args: Vec<OsString> = Vec::new();
    if let Some(graph) = list.shallow_file.as_ref().filter(|_| list.thin) {
        // The VM's graph, as the listing walked it.
        args.extend(["--shallow-file".into(), graph.clone().into_os_string()]);
    }
    args.extend(["pack-objects", "--stdout", "-q", "--delta-base-offset"].map(OsString::from));
    if list.thin {
        // The same walk `rev-list --objects-edge` made: never the sparse one, which may send more, nor a
        // reachability bitmap's (the user's, through the alternates), which takes every object the seeded
        // commit's history reaches for the VM's, though the shallow VM was never sent them.
        args.extend(["--revs", "--thin", "--no-sparse", "--no-use-bitmap-index"].map(OsString::from));
    }
    let mut child = scratch.git().spawn_piped(&args).map_err(git_failed("git pack-objects of the seed"))?;
    let feeder = child.take_stdin().map(|mut stdin| {
        let input = list.input();
        // A pack-objects that stopped reading (killed past the cap) fails this write: its end says why.
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        })
    });
    let copied = match child.take_stdout() {
        Some(out) => std::io::copy(&mut out.take(room.saturating_add(1)), &mut file)?,
        None => 0,
    };
    if copied > room {
        // Dropping the run kills its group; the feeder's write then fails and it ends.
        drop(child);
        if let Some(f) = feeder {
            let _ = f.join();
        }
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Ok(None);
    }
    if let Some(f) = feeder {
        let _ = f.join();
    }
    let finished = child.finish();
    if let Err(e) = finished {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(git_failed("git pack-objects of the seed")(e));
    }
    file.sync_all()?;
    drop(file);
    // Fail closed: a pack holding another number of objects than were listed (and scanned) never goes.
    let count = pack_count(&path, head.len() as u64)?;
    if count != list.objects.len() as u64 {
        let _ = std::fs::remove_file(&path);
        return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::BAD_PACK, message: format!("the seed's pack holds {count} objects where {} were listed and scanned", list.objects.len()) });
    }
    Ok(Some(SeedBody { path, len: head.len() as u64 + copied, manifest: manifest.clone(), objects: count }))
}

/// The object count of the pack at `offset` in `path` (its header: `PACK`, the version, the count).
fn pack_count(path: &std::path::Path, offset: u64) -> Result<u64, BridgeError> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 12];
    f.read_exact(&mut header)?;
    if &header[..4] != b"PACK" {
        return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::BAD_PACK, message: "git pack-objects wrote no pack".into() });
    }
    Ok(u64::from(u32::from_be_bytes([header[8], header[9], header[10], header[11]])))
}

/// The objects `pack` (a pack file) holds, by `index-pack` into a throwaway
/// index of the scratch repository (`verify-pack` would need one too): for
/// tests and the code-out scan, which reads a pack the VM made.
pub fn pack_ids(scratch: &Scratch, pack: &std::path::Path) -> Result<Vec<String>, BridgeError> {
    let idx = scratch.dir().join("listed.idx");
    let _ = std::fs::remove_file(&idx);
    scratch.git().output([std::ffi::OsStr::new("index-pack"), "-o".as_ref(), idx.as_os_str(), pack.as_os_str()]).map_err(git_failed("git index-pack of a pack"))?;
    let mut bytes = Vec::new();
    std::fs::File::open(&idx)?.read_to_end(&mut bytes)?;
    let out = scratch.git().output_stdin(["show-index"], &bytes).map_err(git_failed("git show-index"))?;
    let _ = std::fs::remove_file(&idx);
    Ok(String::from_utf8_lossy(&out).lines().filter_map(|l| l.split(' ').nth(1)).map(str::to_string).collect())
}
