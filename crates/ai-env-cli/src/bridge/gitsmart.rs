//! `box fetch --smart-http` (S9 plan §2, M5): the Mac's own git smart-HTTP
//! v2 client, through the MicroVM endpoint to the VM's `git http-backend`
//! (`shim::gitcgi`), on the data plane's one transport
//! (`dataplane::HttpsEndpoint::send_with`: TLS 1.3, Amazon roots, no proxy,
//! no redirect, a re-mint on 401/403). Three idempotent exchanges, each
//! with `Git-Protocol: version=2`: the advertisement (it must be v2, else
//! `workspace::code::PROTOCOL_DOWNGRADED` naming the `protocol-v2` probe; the
//! object format must match), `ls-refs` (only [`LS_REFS_PREFIXES`]), then
//! `fetch` ([`FETCH_FEATURES`], at most 256 haves, never [`NEVER_SENT`]).
//! The refs pass the manifest rules, `codeout::credential_shaped` and
//! `codeout::box_refs` before any want; the pack then goes through S8's
//! `import` and `promote`, the import's commit-only check (S9) leaving out
//! a ref it takes whose object the pack shows to be a tree or a blob. No
//! token or bearer ever reaches a git process. Frozen in S9 phase 0
//! ([`GitHttp`] and the constants); G2 builds the codec, the demux and the
//! client.
use crate::bridge::agent::AgentTarget;
use crate::bridge::api::AuthToken;
use crate::bridge::dataplane::DpReply;
use crate::bridge::errors::BridgeError;
use std::future::Future;

/// Git smart-HTTP v2 through the endpoint (9418), on `HttpsEndpoint::send_with`: the one transport (TLS 1.3, Amazon roots,
/// no proxy, no redirect; plain http to the lab's agent address). No token or bearer ever reaches a git process.
pub trait GitHttp: Send + Sync {
    /// `GET /workspace.git/info/refs?service=git-upload-pack`: the advertisement, at most `ADVERT_MAX` bytes
    /// (more: `WorkspaceRefused { too_large }`).
    fn info_refs(&self, target: &AgentTarget, token: &AuthToken) -> impl Future<Output = Result<DpReply<Vec<u8>>, BridgeError>> + Send;

    /// `POST /workspace.git/git-upload-pack` with `body` (one v2 command: `ls-refs` or `fetch`): a 200's body
    /// streamed into `sink`, never past `cap` bytes (more: `WorkspaceRefused { too_large }`); the reply's body is
    /// the bytes written. A body cut before its last chunk is `BridgeError::Endpoint`.
    fn upload_pack<W: std::io::Write + Send>(&self, target: &AgentTarget, token: &AuthToken, body: &[u8], sink: &mut W, cap: u64) -> impl Future<Output = Result<DpReply<u64>, BridgeError>> + Send;
}

/// The advertisement and an `ls-refs` answer, at most.
pub const ADVERT_MAX: u64 = 1 << 20;
/// The longest pkt-line, its 4-byte length included.
pub const PKT_MAX: usize = 65520;
/// Characters of a band-3 message kept, scrubbed.
pub const BAND3_MAX: usize = 300;
/// What `ls-refs` asks for (`ref-prefix`): the checkout, the branches, the snapshots, the seeded WIP.
pub const LS_REFS_PREFIXES: [&str; 4] = ["HEAD", "refs/heads/", "refs/wip/", "refs/ai-env/seed-wip"];
/// What `fetch` asks for besides its wants and haves.
pub const FETCH_FEATURES: [&str; 3] = ["thin-pack", "ofs-delta", "no-progress"];
/// What a request never carries (the request builder's test lists them).
pub const NEVER_SENT: [&str; 8] = ["include-tag", "deepen", "deepen-since", "deepen-not", "deepen-relative", "filter", "want-ref", "shallow"];

// ---- the client (G2) -----------------------------------------------------------------------

use crate::bridge::api::MicrovmApi;
use crate::bridge::dataplane::{exchange, Exchange, TokenSource, Verdict};
use crate::wire::frame::CAP_GIT_HTTP_V1;
use crate::wire::workspace::{branch_check, refusal, CodeoutManifest, ObjectFormat, SeedManifest, WsRefusal, CODE_PORT, GIT_REQUEST_MAX, HAVES_MAX, HEADS_PREFIX, SEED_WIP_REF, WIP_REF_PREFIX};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

/// The advertisement's exchange, as the data plane's `exchange` and the errors name it.
pub const INFO_REFS: &str = "GET /workspace.git/info/refs";
/// An `ls-refs` or a `fetch` exchange's.
pub const UPLOAD_PACK: &str = "POST /workspace.git/git-upload-pack";
/// The longest payload of a data pkt-line: [`PKT_MAX`] less its length.
pub const PKT_DATA_MAX: usize = PKT_MAX - 4;
/// A delim-pkt (a section's end), a flush-pkt (a message's) and a
/// response-end-pkt (a stateless response's), as they are written.
const DELIM_PKT: &[u8] = b"0001";
const FLUSH_PKT: &[u8] = b"0000";
const RESPONSE_END_PKT: &[u8] = b"0002";

/// What a `fetch` answer may carry besides its pack's bytes, which
/// [`Demux`] counts against `max_bytes` itself: the pkt-lines' own five
/// bytes a line (one part in 13 000 at most), the sections' headers, the
/// shallow-info lines and dropped progress: a part in 4096 of the cap, plus
/// [`ADVERT_MAX`].
fn answer_cap(max_bytes: u64) -> u64 {
    max_bytes.saturating_add(max_bytes / 4096).saturating_add(ADVERT_MAX)
}

// ---- the pkt-line codec ----

/// One pkt-line (gitprotocol-common): four hex digits of length, itself
/// included, then the payload; `0000`, `0001` and `0002` carry none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkt<'a> {
    /// `0000`: a message's end.
    Flush,
    /// `0001`: a section's end (protocol v2).
    Delim,
    /// `0002`: a response's end on a stateless connection.
    ResponseEnd,
    /// A line's payload.
    Data(&'a [u8]),
}

/// The pkt-line at the start of `buf` and the bytes it takes; `Ok(None)`
/// while `buf` holds less than one whole line. `Err`: a length that is not
/// four hex digits, `0003`, or over [`PKT_MAX`] (never more than four bytes
/// of what came are quoted, escaped).
pub fn parse_pkt(buf: &[u8]) -> Result<Option<(Pkt<'_>, usize)>, String> {
    let Some(head) = buf.get(..4) else { return Ok(None) };
    let len = std::str::from_utf8(head)
        .ok()
        .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|h| usize::from_str_radix(h, 16).ok())
        .ok_or_else(|| format!("a pkt-line length that is not four hex digits ({})", head.iter().flat_map(|b| std::ascii::escape_default(*b)).map(char::from).collect::<String>()))?;
    match len {
        0 => Ok(Some((Pkt::Flush, 4))),
        1 => Ok(Some((Pkt::Delim, 4))),
        2 => Ok(Some((Pkt::ResponseEnd, 4))),
        3 => Err("a pkt-line of length 0003".into()),
        n if n > PKT_MAX => Err(format!("a pkt-line of {n} bytes (at most {PKT_MAX})")),
        n => Ok(buf.get(4..n).map(|data| (Pkt::Data(data), n))),
    }
}

/// `data` as one pkt-line at the end of `out`; `Err` past [`PKT_DATA_MAX`] bytes.
pub fn put_pkt(out: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    if data.len() > PKT_DATA_MAX {
        return Err(format!("a pkt-line of {} bytes (at most {PKT_DATA_MAX})", data.len()));
    }
    out.extend_from_slice(format!("{:04x}", data.len() + 4).as_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// `text` and its LF as one pkt-line: the request builders' own lines (a
/// command, a capability, a feature, a ref prefix, `want` or `have` and an
/// object id), each far under [`PKT_DATA_MAX`].
fn put_text(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(format!("{:04x}{text}\n", text.len() + 5).as_bytes());
}

/// A data line's text: its payload, one trailing LF dropped.
fn line_text(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

/// A whole message's lines to its flush (an advertisement, an `ls-refs`
/// answer), each as [`line_text`]; past the flush, a response-end at most.
/// `Err` (`bad_pack`): a malformed line, a delim or a response-end before
/// the flush, a message cut before it, or bytes after it.
fn message_lines<'a>(body: &'a [u8], route: &str, what: &str) -> Result<Vec<&'a [u8]>, BridgeError> {
    let mut lines = Vec::new();
    let mut at = 0;
    loop {
        match parse_pkt(&body[at..]).map_err(|e| bad_pack(route, &format!("{what}: {e}")))? {
            None => return Err(bad_pack(route, &format!("{what} ended before its flush"))),
            Some((Pkt::Data(data), n)) => {
                lines.push(line_text(data));
                at += n;
            }
            Some((Pkt::Flush, n)) => {
                at += n;
                break;
            }
            Some((Pkt::Delim | Pkt::ResponseEnd, _)) => return Err(bad_pack(route, &format!("{what} holds a section's or a response's end before its flush"))),
        }
    }
    match &body[at..] {
        [] => Ok(lines),
        rest if rest == RESPONSE_END_PKT => Ok(lines),
        _ => Err(bad_pack(route, &format!("{what} goes on past its flush"))),
    }
}

/// `bad_pack` (exit 1): the VM's answer to `route` is no git protocol a request of ours takes.
fn bad_pack(route: &str, what: &str) -> BridgeError {
    BridgeError::WorkspaceFailed { code: refusal::BAD_PACK, message: format!("{route}: {what}") }
}

/// What the VM's git said on band 3 or in an `ERR` line, as `git_failed`
/// (exit 1): one line (`WsRefusal::new`'s: scrubbed, control characters
/// blanked), at most [`BAND3_MAX`] characters of it.
fn vm_git_failed(route: &str, said: &[u8]) -> BridgeError {
    let kept: String = WsRefusal::new(refusal::GIT_FAILED, &String::from_utf8_lossy(said)).message.chars().take(BAND3_MAX).collect();
    BridgeError::WorkspaceFailed { code: refusal::GIT_FAILED, message: format!("{route}: the VM's upload-pack failed: {kept}") }
}

/// An `ERR` line (git's own refusal, before any section) as [`vm_git_failed`].
fn err_line(route: &str, line: &[u8]) -> Option<BridgeError> {
    line.strip_prefix(b"ERR ").map(|said| vm_git_failed(route, said))
}

// ---- the advertisement ----

/// What a protocol v2 capability advertisement says (`GET
/// /workspace.git/info/refs` with `Git-Protocol: version=2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    /// Its `object-format`; sha1 when it names none, as git reads it.
    pub object_format: ObjectFormat,
    /// It named `object-format`: each request names it too (a sha256
    /// server takes no request without it).
    pub names_format: bool,
    /// Its capability lines after `version 2`, as advertised
    /// (`agent=git/2.50.1`, `ls-refs=unborn`, `fetch=shallow wait-for-done`, …).
    pub caps: Vec<String>,
}

/// The advertisement `body` of the VM, whose repository must be of the
/// Mac's object format (`mac`): `version 2` first, then printable
/// capabilities to the flush, `ls-refs` and `fetch` among them. An answer
/// that is no v2 one (`# service=` first, as http-backend writes a v0 one;
/// a ref line; `version 1`) is `protocol_downgraded` (exit 1), naming `ai-env
/// lab run protocol-v2` and plain `box fetch`; another object format, or one
/// this build does not read, is `unsupported_repo`; an `ERR` line, or no
/// `ls-refs` or `fetch`, the VM's git failing (`git_failed`); a malformed
/// message `bad_pack`.
pub fn parse_advert(body: &[u8], mac: ObjectFormat) -> Result<Advert, BridgeError> {
    let first = match parse_pkt(body) {
        Ok(Some((Pkt::Data(data), _))) => line_text(data),
        Ok(_) => return Err(bad_pack(INFO_REFS, "the advertisement holds no line")),
        Err(e) => return Err(bad_pack(INFO_REFS, &format!("the advertisement: {e}"))),
    };
    if let Some(e) = err_line(INFO_REFS, first) {
        return Err(e);
    }
    if first != b"version 2" {
        return Err(BridgeError::WorkspaceFailed {
            code: crate::bridge::workspace::code::PROTOCOL_DOWNGRADED,
            message: format!("{INFO_REFS} answered an advertisement older than protocol v2 to a version 2 request (the endpoint dropped the Git-Protocol header): `ai-env lab run protocol-v2` measures it; plain `ai-env box fetch` fetches through POST /codeout"),
        });
    }
    let mut caps = Vec::new();
    for line in message_lines(body, INFO_REFS, "the advertisement")?.into_iter().skip(1) {
        if let Some(e) = err_line(INFO_REFS, line) {
            return Err(e);
        }
        let cap = std::str::from_utf8(line).ok().filter(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_graphic() || b == b' ')).ok_or_else(|| bad_pack(INFO_REFS, "the advertisement holds a capability that is not printable ASCII"))?;
        caps.push(cap.to_string());
    }
    for needed in ["ls-refs", "fetch"] {
        if !caps.iter().any(|c| c.split_once('=').map_or(c.as_str(), |(k, _)| k) == needed) {
            return Err(BridgeError::WorkspaceFailed { code: refusal::GIT_FAILED, message: format!("{INFO_REFS}: the VM's upload-pack advertises no {needed}") });
        }
    }
    let named = caps.iter().find_map(|c| c.strip_prefix("object-format="));
    let unsupported = |what: String| BridgeError::WorkspaceFailed { code: crate::bridge::workspace::code::UNSUPPORTED_REPO, message: format!("{INFO_REFS}: {what}") };
    let object_format = match named {
        None | Some("sha1") => ObjectFormat::Sha1,
        Some("sha256") => ObjectFormat::Sha256,
        Some(_) => return Err(unsupported("the VM's repository is of an object format this ai-env does not read".into())),
    };
    if object_format != mac {
        return Err(unsupported(format!("the VM's repository is {}, this Mac's {}: a fetch cannot carry its objects", object_format.name(), mac.name())));
    }
    Ok(Advert { object_format, names_format: named.is_some(), caps })
}

/// `command=<command>`, then `object-format` when the advertisement named it.
fn put_command(out: &mut Vec<u8>, advert: &Advert, command: &str) {
    put_text(out, &format!("command={command}"));
    if advert.names_format {
        put_text(out, &format!("object-format={}", advert.object_format.name()));
    }
    out.extend_from_slice(DELIM_PKT);
}

// ---- ls-refs ----

/// The `ls-refs` request (one v2 command): `symrefs` (HEAD's branch),
/// `peel` (a ref that names an annotated tag says so: it is no commit, and
/// goes no further) and exactly the [`LS_REFS_PREFIXES`]: never a tag, a
/// remote-tracking ref, a note or the stash.
#[must_use]
pub fn ls_refs_request(advert: &Advert) -> Vec<u8> {
    let mut out = Vec::new();
    put_command(&mut out, advert, "ls-refs");
    put_text(&mut out, "symrefs");
    put_text(&mut out, "peel");
    for prefix in LS_REFS_PREFIXES {
        put_text(&mut out, &format!("ref-prefix {prefix}"));
    }
    out.extend_from_slice(FLUSH_PKT);
    out
}

/// One ref an `ls-refs` answer lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsRef {
    pub name: String,
    pub oid: String,
    /// `symref-target:`: the ref HEAD names (its branch).
    pub symref: Option<String>,
    /// `peeled:`: the ref names an annotated tag, which peels to this.
    pub peeled: Option<String>,
}

/// An `ls-refs` answer: `<oid> <name>[ symref-target:<ref>][ peeled:<oid>]`
/// a line to the flush, each id one of `format`'s (any other attribute,
/// which no request of ours asks for, is left aside). A ref named twice, a
/// line of another shape or a malformed message is `bad_pack`; an `ERR`
/// line `git_failed`; a ref whose name is no UTF-8 is left out (no manifest
/// can carry it).
pub fn parse_ls_refs(body: &[u8], format: ObjectFormat) -> Result<Vec<LsRef>, BridgeError> {
    let id = |field: &[u8]| std::str::from_utf8(field).ok().filter(|s| format.is_id(s)).map(str::to_string).ok_or_else(|| bad_pack(UPLOAD_PACK, &format!("the ls-refs answer names an id that is not a {} object id", format.name())));
    let mut out: Vec<LsRef> = Vec::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in message_lines(body, UPLOAD_PACK, "the ls-refs answer")? {
        if let Some(e) = err_line(UPLOAD_PACK, line) {
            return Err(e);
        }
        let mut fields = line.split(|b| *b == b' ');
        let (Some(oid), Some(name)) = (fields.next(), fields.next().filter(|n| !n.is_empty())) else {
            return Err(bad_pack(UPLOAD_PACK, "the ls-refs answer holds a line that names no ref"));
        };
        let mut found = LsRef { name: String::new(), oid: id(oid)?, symref: None, peeled: None };
        for attr in fields {
            if let Some(target) = attr.strip_prefix(b"symref-target:") {
                found.symref = std::str::from_utf8(target).ok().map(str::to_string);
            } else if let Some(peeled) = attr.strip_prefix(b"peeled:") {
                found.peeled = Some(id(peeled)?);
            }
        }
        let Ok(name) = std::str::from_utf8(name) else { continue };
        if !names.insert(name.to_string()) {
            return Err(bad_pack(UPLOAD_PACK, "the ls-refs answer names a ref twice"));
        }
        found.name = name.to_string();
        out.push(found);
    }
    Ok(out)
}

/// The code-out manifest an `ls-refs` answer stands for, made by the VM
/// helper's own rules (`shim::wshelper`'s code-out listing), so both modes
/// carry the same refs into `codeout::import`: the branches, the snapshots
/// (`refs/wip/*`) and the seeded WIP, each passing the manifest's check on
/// its own; `head` HEAD's commit; `branch` the one HEAD names when git takes
/// its name, else HEAD among the refs (detached). Of the helper's rule that
/// a ref names a commit, only a tag shows here (`peel`), and its ref is left
/// out; a tree or a blob shows once the pack is on the Mac, where
/// `codeout::import` leaves its ref out (counted, unless its clash check
/// named it skipped first). No snapshot is ever made
/// here (`wip_ref` none). No HEAD (a repository with no commit checked out)
/// is `not_seeded`, as the helper answers.
pub fn manifest_of(refs: &[LsRef], format: ObjectFormat) -> Result<CodeoutManifest, BridgeError> {
    let Some(head) = refs.iter().find(|r| r.name == "HEAD") else {
        return Err(BridgeError::WorkspaceRefused { code: refusal::NOT_SEEDED, message: format!("{UPLOAD_PACK}: the VM's repository has no commit checked out") });
    };
    let commit = head.peeled.clone().unwrap_or_else(|| head.oid.clone());
    let branch = head.symref.as_deref().and_then(|t| t.strip_prefix(HEADS_PREFIX)).filter(|b| branch_check(b).is_ok()).map(str::to_string);
    let alone = CodeoutManifest { v: SeedManifest::V, object_format: format, refs: BTreeMap::new(), head: commit.clone(), branch, wip_ref: None, wip_skipped: None };
    let mut manifest = alone.clone();
    for r in refs.iter().filter(|r| r.peeled.is_none() && (r.name.starts_with(HEADS_PREFIX) || r.name.starts_with(WIP_REF_PREFIX) || r.name == SEED_WIP_REF)) {
        let mut one = alone.clone();
        one.refs.insert(r.name.clone(), r.oid.clone());
        if one.check().is_ok() {
            manifest.refs.insert(r.name.clone(), r.oid.clone());
        }
    }
    if manifest.branch.is_none() {
        manifest.refs.insert("HEAD".to_string(), commit);
    }
    manifest.check().map_err(|e| BridgeError::WorkspaceFailed { code: refusal::BAD_REFS, message: format!("{UPLOAD_PACK}: the manifest of the VM's refs {e}") })?;
    Ok(manifest)
}

// ---- fetch ----

/// The `fetch` request (one v2 command): [`FETCH_FEATURES`], a `want` for
/// each of `wants`, a `have` for each of `haves` in their order
/// (`codeout::haves_of`'s), at most [`HAVES_MAX`] of them, then `done`: no
/// negotiation, the answer is the pack. Never one of [`NEVER_SENT`]. `Err`:
/// no want, or an id that is not one of the format's (`Config`, exit 1); a
/// request over the VM's [`GIT_REQUEST_MAX`] (`too_large`, exit 9).
pub fn fetch_request(advert: &Advert, wants: &[String], haves: &[String]) -> Result<Vec<u8>, BridgeError> {
    let format = advert.object_format;
    let haves = &haves[..haves.len().min(HAVES_MAX)];
    if wants.is_empty() {
        return Err(BridgeError::Config(format!("{UPLOAD_PACK}: a fetch with nothing to want")));
    }
    if wants.iter().chain(haves).any(|id| !format.is_id(id)) {
        return Err(BridgeError::Config(format!("{UPLOAD_PACK}: a want or a have that is not a {} object id", format.name())));
    }
    let mut out = Vec::new();
    put_command(&mut out, advert, "fetch");
    for feature in FETCH_FEATURES {
        put_text(&mut out, feature);
    }
    for want in wants {
        put_text(&mut out, &format!("want {want}"));
    }
    for have in haves {
        put_text(&mut out, &format!("have {have}"));
    }
    put_text(&mut out, "done");
    out.extend_from_slice(FLUSH_PKT);
    if out.len() as u64 > GIT_REQUEST_MAX {
        return Err(BridgeError::WorkspaceRefused {
            code: refusal::TOO_LARGE,
            message: format!("{UPLOAD_PACK}: the fetch request wants {} commits, over the {} a VM takes (plain box fetch carries them)", wants.len(), crate::bridge::workspace::snapshot::human_bytes(GIT_REQUEST_MAX)),
        });
    }
    Ok(out)
}

/// Where a [`Demux`] stands in a `fetch` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Before a section's header.
    Header,
    /// In `shallow-info`, to its delim.
    Shallow,
    /// In `packfile`, to the flush that ends the answer.
    Pack,
    /// After that flush: one response-end may follow.
    Ended,
    /// After the response-end.
    Closed,
}

/// The streaming reader of a `fetch` answer: the [`std::io::Write`] sink
/// [`GitHttp::upload_pack`] writes it into as it comes, in any chunking. The
/// `shallow-info` section is read and left aside; in the `packfile` section
/// band 1 goes to `pack`, never past `max_bytes` (more: `too_large`, exit 9),
/// band 2 (progress) is dropped, and band 3, like an `ERR` line before any
/// section, is the VM's git failing (`git_failed`, scrubbed, at most
/// [`BAND3_MAX`] characters); another section (`acknowledgments` after our
/// `done`, `wanted-refs`, `packfile-uris`: nothing we ask for), band or shape
/// is `bad_pack`. The first refusal stops it: every later write fails, and
/// [`Demux::take_failure`] hands the refusal over. Beside what it was
/// handed, it holds one partial pkt-line at most.
pub struct Demux<W> {
    pack: W,
    max_bytes: u64,
    written: u64,
    buf: Vec<u8>,
    part: Part,
    failure: Option<BridgeError>,
    failed: bool,
}

impl<W: Write> Demux<W> {
    /// A reader writing the pack into `pack`, at most `max_bytes` of it.
    #[must_use]
    pub fn new(pack: W, max_bytes: u64) -> Demux<W> {
        Demux { pack, max_bytes, written: 0, buf: Vec::new(), part: Part::Header, failure: None, failed: false }
    }

    /// The refusal that stopped it (once).
    pub fn take_failure(&mut self) -> Option<BridgeError> {
        self.failure.take()
    }

    /// The answer read whole: `pack` and the pack's bytes written to it.
    /// `Err`: the refusal that stopped it, or `bad_pack` for an answer that
    /// ended inside a pkt-line or before its flush.
    pub fn finish(mut self) -> Result<(W, u64), BridgeError> {
        if let Some(e) = self.failure.take() {
            return Err(e);
        }
        if self.failed {
            return Err(bad_pack(UPLOAD_PACK, "the answer was refused"));
        }
        if !self.buf.is_empty() {
            return Err(bad_pack(UPLOAD_PACK, "the answer ended inside a pkt-line"));
        }
        if !matches!(self.part, Part::Ended | Part::Closed) {
            return Err(bad_pack(UPLOAD_PACK, "the answer ended before its flush"));
        }
        self.pack.flush()?;
        Ok((self.pack, self.written))
    }

    /// Each whole pkt-line `data` completes, in order.
    fn feed(&mut self, data: &[u8]) -> Result<(), BridgeError> {
        let Demux { pack, max_bytes, written, buf, part, .. } = self;
        buf.extend_from_slice(data);
        let mut at = 0;
        let fed = loop {
            match parse_pkt(&buf[at..]) {
                Err(e) => break Err(bad_pack(UPLOAD_PACK, &format!("the answer: {e}"))),
                Ok(None) => break Ok(()),
                Ok(Some((pkt, n))) => {
                    if let Err(e) = step(part, pack, written, *max_bytes, pkt) {
                        break Err(e);
                    }
                    at += n;
                }
            }
        };
        buf.drain(..at);
        fed
    }
}

/// One pkt-line of a `fetch` answer, at `part`.
fn step<W: Write>(part: &mut Part, pack: &mut W, written: &mut u64, max_bytes: u64, pkt: Pkt<'_>) -> Result<(), BridgeError> {
    match (*part, pkt) {
        (Part::Header, Pkt::Data(data)) => {
            let line = line_text(data);
            if let Some(e) = err_line(UPLOAD_PACK, line) {
                return Err(e);
            }
            *part = match line {
                b"shallow-info" => Part::Shallow,
                b"packfile" => Part::Pack,
                _ => return Err(bad_pack(UPLOAD_PACK, "the answer holds a section no request of ours asks for")),
            };
        }
        (Part::Header, Pkt::Flush) => return Err(bad_pack(UPLOAD_PACK, "the answer ended without its packfile section")),
        (Part::Shallow, Pkt::Data(_)) => {}
        (Part::Shallow, Pkt::Delim) => *part = Part::Header,
        (Part::Pack, Pkt::Data(data)) => match data.split_first() {
            Some((1, bytes)) => {
                *written = written.saturating_add(bytes.len() as u64);
                if *written > max_bytes {
                    return Err(BridgeError::WorkspaceRefused {
                        code: refusal::TOO_LARGE,
                        message: format!("{UPLOAD_PACK}: the pack is over {} (box fetch --max-mib, [seed].max_fetch_mib)", crate::bridge::workspace::snapshot::human_bytes(max_bytes)),
                    });
                }
                pack.write_all(bytes)?;
            }
            Some((2, _)) => {}
            Some((3, said)) => return Err(vm_git_failed(UPLOAD_PACK, said)),
            Some((band, _)) => return Err(bad_pack(UPLOAD_PACK, &format!("the packfile section holds a line on band {band}"))),
            None => return Err(bad_pack(UPLOAD_PACK, "the packfile section holds a line without its band")),
        },
        (Part::Pack, Pkt::Flush) => *part = Part::Ended,
        (Part::Ended, Pkt::ResponseEnd) => *part = Part::Closed,
        (Part::Ended | Part::Closed, _) => return Err(bad_pack(UPLOAD_PACK, "the answer goes on past its flush")),
        (Part::Shallow, Pkt::Flush) => return Err(bad_pack(UPLOAD_PACK, "the answer ended in its shallow-info section")),
        (_, _) => return Err(bad_pack(UPLOAD_PACK, "the answer holds a section's or a response's end out of its place")),
    }
    Ok(())
}

impl<W: Write> Write for Demux<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.failed {
            return Err(std::io::Error::other("the fetch answer was refused already"));
        }
        match self.feed(data) {
            Ok(()) => Ok(data.len()),
            Err(e) => {
                let said = e.to_string();
                self.failure = Some(e);
                self.failed = true;
                Err(std::io::Error::other(said))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.pack.flush()
    }
}

// ---- the exchanges ----

/// The client's three exchanges with one VM, each through the data plane's
/// `exchange` on the code port, idempotent, its 404 an image without
/// [`CAP_GIT_HTTP_V1`] (exit 7, `make deploy`): a 401 or 403 re-mints once,
/// then exit 7; `busy` waits; a 502 or 503 asks GetMicrovm (gone: exit 8);
/// an answer cut before its end is asked once more, its sink started again.
pub struct Client<'a, A, G, T> {
    /// The control plane (GetMicrovm after a 502 or 503).
    pub api: &'a A,
    pub tokens: &'a T,
    /// The transport (`dataplane::HttpsEndpoint`).
    pub git: &'a G,
    pub target: &'a AgentTarget,
}

impl<A: MicrovmApi, G: GitHttp, T: TokenSource> Client<'_, A, G, T> {
    /// The data plane's exchange of `route`.
    fn exchange_of(&self, route: &'static str) -> Exchange<'_, A, T> {
        Exchange { api: self.api, tokens: self.tokens, vm_id: &self.target.vm_id, port: CODE_PORT, cap: CAP_GIT_HTTP_V1, route, deadline: None, idempotent: true }
    }

    /// The advertisement, checked against the Mac's object format `mac` ([`parse_advert`]).
    pub async fn advertise(&self, mac: ObjectFormat) -> Result<Advert, BridgeError> {
        let (reply, verdict) = exchange(&self.exchange_of(INFO_REFS), |t| async move { self.git.info_refs(self.target, &t).await }).await?;
        parse_advert(&answered(INFO_REFS, reply, &verdict)?, mac)
    }

    /// `ls-refs` ([`ls_refs_request`]), its answer at most [`ADVERT_MAX`] bytes, parsed ([`parse_ls_refs`]).
    pub async fn ls_refs(&self, advert: &Advert) -> Result<Vec<LsRef>, BridgeError> {
        let request = ls_refs_request(advert);
        let (reply, verdict) = exchange(&self.exchange_of(UPLOAD_PACK), |t| {
            let request = &request;
            async move {
                let mut body = Vec::new();
                let reply = self.git.upload_pack(self.target, &t, request, &mut body, ADVERT_MAX).await?;
                Ok(DpReply { status: reply.status, body: reply.body.map(|_| body), refusal: reply.refusal, proxy_error: reply.proxy_error, retry_after_s: reply.retry_after_s })
            }
        })
        .await?;
        parse_ls_refs(&answered(UPLOAD_PACK, reply, &verdict)?, advert.object_format)
    }

    /// `fetch` ([`fetch_request`]): the pack into `dest` (made anew, 0600,
    /// never through a symlink, at each attempt), at most `max_bytes` of it
    /// ([`Demux`]); its bytes. Both limits stay clear of the VM's own cut
    /// (`GIT_RESPONSE_MAX`, which the shim's stream reaches anywhere within
    /// one read of it, a read past it dropped): `max_bytes` at most
    /// `GIT_RESPONSE_MAX` less two [`ADVERT_MAX`], the answer's cap at most
    /// one less, so an answer that large is `too_large` (exit 9) on its first
    /// request, never a cut answer asked again (exit 7 after twice the bytes).
    pub async fn fetch_pack(&self, advert: &Advert, wants: &[String], haves: &[String], dest: &Path, max_bytes: u64) -> Result<u64, BridgeError> {
        use crate::wire::workspace::GIT_RESPONSE_MAX;
        let request = fetch_request(advert, wants, haves)?;
        let max_bytes = max_bytes.min(GIT_RESPONSE_MAX - 2 * ADVERT_MAX);
        let cap = answer_cap(max_bytes).min(GIT_RESPONSE_MAX - ADVERT_MAX);
        let (reply, verdict) = exchange(&self.exchange_of(UPLOAD_PACK), |t| {
            let request = &request;
            async move {
                let mut demux = Demux::new(pack_file(dest)?, max_bytes);
                let sent = self.git.upload_pack(self.target, &t, request, &mut demux, cap).await;
                // A refusal of the demux's failed the sink's write: it is the answer's.
                if let Some(e) = demux.take_failure() {
                    return Err(e);
                }
                let reply = sent?;
                if reply.status != 200 {
                    return Ok(reply);
                }
                let (file, bytes) = demux.finish()?;
                file.sync_all()?;
                Ok(DpReply { body: Some(bytes), ..reply })
            }
        })
        .await?;
        answered(UPLOAD_PACK, reply, &verdict)
    }
}

/// A 200's body; any other answer that stands (a 204, a 409 `dirty` the git
/// routes never send) is the VM breaking the protocol.
fn answered<R>(route: &str, reply: DpReply<R>, verdict: &Verdict) -> Result<R, BridgeError> {
    match (reply.status, verdict, reply.body) {
        (200, Verdict::Done, Some(body)) => Ok(body),
        (status, _, _) => Err(BridgeError::Protocol(format!("{route} answered HTTP {status} where a git answer was due"))),
    }
}

/// `dest` made anew (truncated when there), 0600, never through a symlink.
fn pack_file(dest: &Path) -> Result<std::fs::File, BridgeError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dest)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::errors::CliError;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn exit(e: BridgeError) -> i32 {
        CliError::from(e).exit_code()
    }

    /// A refusal's code (`other` for any other error).
    fn code(e: &BridgeError) -> &'static str {
        match e {
            BridgeError::WorkspaceFailed { code, .. } | BridgeError::WorkspaceRefused { code, .. } => code,
            _ => "other",
        }
    }

    /// `texts` as pkt-lines, each with its LF.
    fn pkts(texts: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for t in texts {
            put_text(&mut out, t);
        }
        out
    }

    /// A message: `texts`, then its flush.
    fn message(texts: &[&str]) -> Vec<u8> {
        [pkts(texts), FLUSH_PKT.to_vec()].concat()
    }

    /// A request's lines: each data line's text, `0000` and `0001` as written.
    fn decoded(mut body: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        while !body.is_empty() {
            let (pkt, n) = parse_pkt(body).unwrap().expect("whole lines");
            out.push(match pkt {
                Pkt::Flush => "0000".to_string(),
                Pkt::Delim => "0001".to_string(),
                Pkt::ResponseEnd => "0002".to_string(),
                Pkt::Data(d) => String::from_utf8(line_text(d).to_vec()).unwrap(),
            });
            body = &body[n..];
        }
        out
    }

    /// git 2.50's v2 advertisement, as the image's http-backend writes it.
    fn sha1_advert() -> Vec<u8> {
        message(&["version 2", "agent=git/2.50.1", "ls-refs=unborn", "fetch=shallow wait-for-done", "server-option", "object-format=sha1"])
    }

    fn advert() -> Advert {
        parse_advert(&sha1_advert(), ObjectFormat::Sha1).unwrap()
    }

    /// A `fetch` answer: a `shallow-info` section of `shallow` lines (none:
    /// no section; git writes them without a LF), then `packfile` with each
    /// `(band, bytes)` line, then `tail` (the flush, or not).
    fn answer(shallow: &[&str], lines: &[(u8, &[u8])], tail: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if !shallow.is_empty() {
            put_text(&mut out, "shallow-info");
            for s in shallow {
                put_pkt(&mut out, s.as_bytes()).unwrap();
            }
            out.extend_from_slice(DELIM_PKT);
        }
        put_text(&mut out, "packfile");
        for (band, bytes) in lines {
            put_pkt(&mut out, &[&[*band][..], bytes].concat()).unwrap();
        }
        out.extend_from_slice(tail);
        out
    }

    /// `answer` through a fresh [`Demux`] (at most `max` pack bytes), `chunk` bytes a write: the pack, or the refusal.
    fn demuxed(answer: &[u8], max: u64, chunk: usize) -> Result<Vec<u8>, BridgeError> {
        let mut d = Demux::new(Vec::new(), max);
        for part in answer.chunks(chunk.max(1)) {
            if d.write_all(part).is_err() {
                return Err(d.take_failure().expect("the refusal behind the failed write"));
            }
        }
        let (pack, n) = d.finish()?;
        assert_eq!(n, pack.len() as u64);
        Ok(pack)
    }

    /// The real git in `dir`, with neither the system's nor a global config
    /// nor any inherited `GIT_*`, a fixed author and date; `v2`: as
    /// http-backend runs upload-pack for a `Git-Protocol: version=2` request.
    fn git_cmd(dir: &Path, v2: bool) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(dir);
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(k);
            }
        }
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").env("LC_ALL", "C");
        for (k, v) in [("GIT_AUTHOR_NAME", "t"), ("GIT_AUTHOR_EMAIL", "t@ai-env.invalid"), ("GIT_COMMITTER_NAME", "t"), ("GIT_COMMITTER_EMAIL", "t@ai-env.invalid")] {
            cmd.env(k, v);
        }
        cmd.env("GIT_AUTHOR_DATE", "2026-10-18T08:00:00+00:00").env("GIT_COMMITTER_DATE", "2026-10-18T08:00:00+00:00");
        if v2 {
            cmd.env("GIT_PROTOCOL", "version=2");
        }
        cmd
    }

    /// `git args` in `dir` with `stdin`: its stdout; a failure panics with its stderr.
    fn git_io(dir: &Path, args: &[&str], stdin: &[u8], v2: bool) -> Vec<u8> {
        let mut child = git_cmd(dir, v2).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let bytes = stdin.to_vec();
        let feeder = std::thread::spawn(move || {
            let _ = input.write_all(&bytes);
        });
        let out = child.wait_with_output().unwrap();
        feeder.join().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        String::from_utf8(git_io(dir, args, b"", false)).unwrap().trim().to_string()
    }

    /// A repository at `dir` on `main` with one empty commit: its id.
    fn repo(dir: &Path) -> String {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q", "-b", "main"]);
        git(dir, &["commit", "-q", "--allow-empty", "-m", "one"]);
        git(dir, &["rev-parse", "HEAD"])
    }

    fn target() -> AgentTarget {
        AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: crate::wire::redact::Secret::new("t".into()), vpc: true, shell: false }
    }

    /// Tokens that are always there.
    struct Tokens;

    impl TokenSource for Tokens {
        async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
            Ok(AuthToken { headers: BTreeMap::new(), port, expires_at_unix: u64::MAX })
        }
    }

    /// The real upload-pack of `repo` as http-backend runs it (protocol v2,
    /// stateless), each answer written in 1000-byte pieces.
    struct UploadPack {
        repo: PathBuf,
    }

    impl GitHttp for UploadPack {
        async fn info_refs(&self, _: &AgentTarget, _: &AuthToken) -> Result<DpReply<Vec<u8>>, BridgeError> {
            Ok(DpReply::ok(200, git_io(&self.repo, &["upload-pack", "--http-backend-info-refs", "."], b"", true)))
        }

        async fn upload_pack<W: Write + Send>(&self, _: &AgentTarget, _: &AuthToken, body: &[u8], sink: &mut W, cap: u64) -> Result<DpReply<u64>, BridgeError> {
            let answer = git_io(&self.repo, &["upload-pack", "--stateless-rpc", "."], body, true);
            assert!(answer.len() as u64 <= cap, "{} bytes, cap {cap}", answer.len());
            for piece in answer.chunks(1000) {
                sink.write_all(piece)?;
            }
            Ok(DpReply::ok(200, answer.len() as u64))
        }
    }

    /// A transport answering from a script: each `upload_pack` takes the
    /// next `(status, body, cut)`, writes a 200's body in 1000-byte pieces
    /// (never past the cap), and with `cut` then fails as an answer cut
    /// before its last chunk does (`Endpoint`). It keeps the requests.
    struct Canned {
        answers: std::sync::Mutex<std::collections::VecDeque<(u16, Vec<u8>, bool)>>,
        requests: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl Canned {
        fn new(answers: Vec<(u16, Vec<u8>, bool)>) -> Canned {
            Canned { answers: std::sync::Mutex::new(answers.into()), requests: std::sync::Mutex::new(Vec::new()) }
        }

        fn requests(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl GitHttp for Canned {
        async fn info_refs(&self, _: &AgentTarget, _: &AuthToken) -> Result<DpReply<Vec<u8>>, BridgeError> {
            Ok(DpReply::ok(200, sha1_advert()))
        }

        async fn upload_pack<W: Write + Send>(&self, _: &AgentTarget, _: &AuthToken, body: &[u8], sink: &mut W, cap: u64) -> Result<DpReply<u64>, BridgeError> {
            self.requests.lock().unwrap().push(body.to_vec());
            let (status, answer, cut) = self.answers.lock().unwrap().pop_front().expect("a scripted answer");
            if status != 200 {
                return Ok(DpReply::status(status));
            }
            let mut written = 0u64;
            for piece in answer.chunks(1000) {
                written += piece.len() as u64;
                if written > cap {
                    return Err(BridgeError::WorkspaceRefused { code: refusal::TOO_LARGE, message: "over the cap".into() });
                }
                sink.write_all(piece)?;
            }
            if cut {
                return Err(BridgeError::Endpoint("the answer was cut before its last chunk".into()));
            }
            Ok(DpReply::ok(200, written))
        }
    }

    /// The codec reads flush, delim and response-end, a data line, and waits
    /// for a line not yet whole; it refuses `0003`, a length over `PKT_MAX`
    /// and one that is not four hex digits; the writer refuses a payload over
    /// `PKT_DATA_MAX`. Through each reader, a malformed or truncated message,
    /// a section without its flush, and bytes past it, are `bad_pack` (exit 1).
    #[test]
    fn pkt_lines_refuse_bad_lengths() {
        assert_eq!(parse_pkt(b"0000rest").unwrap(), Some((Pkt::Flush, 4)));
        assert_eq!(parse_pkt(b"0001").unwrap(), Some((Pkt::Delim, 4)));
        assert_eq!(parse_pkt(b"0002").unwrap(), Some((Pkt::ResponseEnd, 4)));
        assert_eq!(parse_pkt(b"0009done\nmore").unwrap(), Some((Pkt::Data(b"done\n"), 9)));
        assert_eq!(parse_pkt(b"000ADONE\n\n").unwrap(), Some((Pkt::Data(b"DONE\n\n"), 10)), "upper-case hex, as git reads it");
        for partial in [&b""[..], b"00", b"0010abc", b"fff0"] {
            assert_eq!(parse_pkt(partial).unwrap(), None, "{partial:?}");
        }
        for bad in [&b"0003"[..], b"fff1", b"ffff", b"00g0", b"-001", b" 00a"] {
            assert!(parse_pkt(bad).is_err(), "{bad:?}");
        }
        let mut longest = Vec::new();
        put_pkt(&mut longest, &vec![b'x'; PKT_DATA_MAX]).unwrap();
        assert_eq!((&longest[..4], parse_pkt(&longest).unwrap().map(|(_, n)| n)), (&b"fff0"[..], Some(PKT_MAX)));
        assert!(put_pkt(&mut Vec::new(), &vec![b'x'; PKT_DATA_MAX + 1]).is_err());
        let bad_pack_exit = |e: BridgeError| {
            assert_eq!(code(&e), refusal::BAD_PACK, "{e:?}");
            exit(e)
        };
        // The advertisement.
        let whole = sha1_advert();
        for body in [whole[..whole.len() - 6].to_vec(), pkts(&["version 2", "ls-refs", "fetch"]), b"0003".to_vec(), [pkts(&["version 2"]), b"fff1".to_vec()].concat(), [whole.clone(), pkts(&["more"])].concat(), Vec::new()] {
            assert_eq!(bad_pack_exit(parse_advert(&body, ObjectFormat::Sha1).unwrap_err()), 1);
        }
        assert!(parse_advert(&[whole, RESPONSE_END_PKT.to_vec()].concat(), ObjectFormat::Sha1).is_ok(), "a response-end past the flush");
        // An ls-refs answer.
        let line = format!("{} refs/heads/main", "a".repeat(40));
        let refs = message(&[&line]);
        assert_eq!(parse_ls_refs(&refs, ObjectFormat::Sha1).unwrap().len(), 1);
        for body in [refs[..refs.len() - 7].to_vec(), pkts(&[&line]), b"0003".to_vec(), [pkts(&[&line]), DELIM_PKT.to_vec(), FLUSH_PKT.to_vec()].concat(), message(&["refs/heads/main"]), message(&[&line, &line])] {
            assert_eq!(bad_pack_exit(parse_ls_refs(&body, ObjectFormat::Sha1).unwrap_err()), 1);
        }
        // A fetch answer: a length over the max, one cut inside a line, a packfile section without its flush, a delim in it.
        let pack: &[u8] = b"PACK-bytes";
        let good = answer(&[], &[(1, pack)], FLUSH_PKT);
        assert_eq!(demuxed(&good, 100, 3).unwrap(), pack);
        let shallow_only = [pkts(&["shallow-info"]), b"000dshallow x".to_vec(), FLUSH_PKT.to_vec()].concat();
        for body in [[pkts(&["packfile"]), b"fff1".to_vec()].concat(), good[..good.len() - 6].to_vec(), answer(&[], &[(1, pack)], b""), answer(&[], &[(1, pack)], DELIM_PKT), shallow_only, message(&[]), [good.clone(), pkts(&["more"])].concat()] {
            assert_eq!(bad_pack_exit(demuxed(&body, 100, 3).unwrap_err()), 1);
        }
    }

    /// A v0 answer to the v2 request (the endpoint dropped `Git-Protocol`):
    /// http-backend's (`# service=` first), upload-pack's own (a ref line
    /// first) and a `version 1` one are `protocol_downgraded` (exit 1),
    /// naming `ai-env lab run protocol-v2` and plain `box fetch`; the real
    /// git's v2 advertisement parses. Another object format than the Mac's,
    /// or one this build does not read, is `unsupported_repo`; none named is
    /// sha1; a v2 advertisement without `fetch` is the VM's git failing.
    #[test]
    fn a_v0_advertisement_is_refused_naming_protocol_v2() {
        let tmp = tempfile::tempdir().unwrap();
        let vm = tmp.path().join("vm");
        repo(&vm);
        let v0 = git_io(&vm, &["upload-pack", "--http-backend-info-refs", "."], b"", false);
        let service = [message(&["# service=git-upload-pack"]), v0.clone()].concat();
        let v1 = [pkts(&["version 1"]), v0.clone()].concat();
        for body in [service, v0, v1] {
            let e = parse_advert(&body, ObjectFormat::Sha1).unwrap_err();
            let text = e.to_string();
            assert_eq!(code(&e), crate::bridge::workspace::code::PROTOCOL_DOWNGRADED, "{text}");
            assert!(text.contains("ai-env lab run protocol-v2") && text.contains("plain `ai-env box fetch`"), "{text}");
            assert_eq!(exit(e), 1);
        }
        let v2 = git_io(&vm, &["upload-pack", "--http-backend-info-refs", "."], b"", true);
        let real = parse_advert(&v2, ObjectFormat::Sha1).unwrap();
        assert_eq!((real.object_format, real.names_format), (ObjectFormat::Sha1, true));
        assert!(real.caps.iter().any(|c| c.starts_with("fetch")) && real.caps.iter().any(|c| c.starts_with("ls-refs")), "{:?}", real.caps);
        let e = parse_advert(&v2, ObjectFormat::Sha256).unwrap_err();
        assert!(e.to_string().contains("the VM's repository is sha1, this Mac's sha256"), "{e}");
        assert_eq!((code(&e), exit(e)), (crate::bridge::workspace::code::UNSUPPORTED_REPO, 1));
        let with_format = |f: &str| message(&["version 2", "ls-refs", "fetch", &format!("object-format={f}")]);
        assert_eq!(parse_advert(&with_format("sha256"), ObjectFormat::Sha256).unwrap().object_format, ObjectFormat::Sha256);
        assert_eq!(code(&parse_advert(&with_format("sha3"), ObjectFormat::Sha1).unwrap_err()), crate::bridge::workspace::code::UNSUPPORTED_REPO);
        let unnamed = parse_advert(&message(&["version 2", "ls-refs", "fetch"]), ObjectFormat::Sha1).unwrap();
        assert_eq!(unnamed, Advert { object_format: ObjectFormat::Sha1, names_format: false, caps: vec!["ls-refs".into(), "fetch".into()] }, "none named: sha1, as git reads it");
        let e = parse_advert(&message(&["version 2", "ls-refs=unborn"]), ObjectFormat::Sha1).unwrap_err();
        assert_eq!((code(&e), exit(e)), (refusal::GIT_FAILED, 1));
        assert_eq!(code(&parse_advert(&message(&["version 2", "ls-refs", "fetch", "bad\u{7}cap"]), ObjectFormat::Sha1).unwrap_err()), refusal::BAD_PACK);
    }

    /// `ls-refs` asks for HEAD (its branch through `symrefs`), the branches,
    /// the snapshots and the seeded WIP, with each ref's peel, and nothing
    /// else: the request's lines exactly. Against the real upload-pack of a
    /// repository that also holds a tag, a remote-tracking ref, notes, the
    /// stash, `refs/ai-env/seed` and a branch naming an annotated tag, the
    /// answer lists only the four prefixes' refs, and the manifest the
    /// helper's rules make of it carries only the branches, the snapshot and
    /// the seeded WIP that name a commit.
    #[test]
    fn ls_refs_asks_only_heads_wip_seed_wip_head() {
        let request = ls_refs_request(&advert());
        assert_eq!(decoded(&request), ["command=ls-refs", "object-format=sha1", "0001", "symrefs", "peel", "ref-prefix HEAD", "ref-prefix refs/heads/", "ref-prefix refs/wip/", "ref-prefix refs/ai-env/seed-wip", "0000"]);
        assert!(!decoded(&ls_refs_request(&Advert { names_format: false, ..advert() })).iter().any(|l| l.starts_with("object-format")));
        let tmp = tempfile::tempdir().unwrap();
        let vm = tmp.path().join("vm");
        let one = repo(&vm);
        git(&vm, &["commit", "-q", "--allow-empty", "-m", "two"]);
        let two = git(&vm, &["rev-parse", "HEAD"]);
        git(&vm, &["branch", "dev", &one]);
        git(&vm, &["tag", "-a", "v1", "-m", "a tag", &one]);
        let tag = git(&vm, &["rev-parse", "v1"]);
        for (name, id) in [("refs/remotes/origin/main", &one), ("refs/notes/commits", &one), ("refs/stash", &one), ("refs/ai-env/seed", &one), ("refs/ai-env/seed-wip", &two), ("refs/ai-env/seed-wipe", &two), ("refs/wip/20261018T080000Z-1", &two)] {
            git(&vm, &["update-ref", name, id]);
        }
        // A branch naming the annotated tag: git refuses to write one, the agent writes the file.
        std::fs::write(vm.join(".git/refs/heads/tagged"), format!("{tag}\n")).unwrap();
        let refs = parse_ls_refs(&git_io(&vm, &["upload-pack", "--stateless-rpc", "."], &request, true), ObjectFormat::Sha1).unwrap();
        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["HEAD", "refs/ai-env/seed-wip", "refs/ai-env/seed-wipe", "refs/heads/dev", "refs/heads/main", "refs/heads/tagged", "refs/wip/20261018T080000Z-1"]);
        assert_eq!((refs[0].oid.as_str(), refs[0].symref.as_deref()), (two.as_str(), Some("refs/heads/main")));
        assert_eq!(refs.iter().find(|r| r.name == "refs/heads/tagged").and_then(|r| r.peeled.as_deref()), Some(one.as_str()));
        let m = manifest_of(&refs, ObjectFormat::Sha1).unwrap();
        let kept: Vec<&str> = m.refs.keys().map(String::as_str).collect();
        assert_eq!(kept, ["refs/ai-env/seed-wip", "refs/heads/dev", "refs/heads/main", "refs/wip/20261018T080000Z-1"]);
        assert_eq!((m.head.as_str(), m.branch.as_deref(), m.wip_ref.as_deref(), m.check()), (two.as_str(), Some("main"), None, Ok(())));
        // Detached: HEAD itself is a ref; no HEAD at all is a VM never seeded (exit 9).
        let detached = vec![LsRef { name: "HEAD".into(), oid: one.clone(), symref: None, peeled: None }];
        let m = manifest_of(&detached, ObjectFormat::Sha1).unwrap();
        assert_eq!((m.branch, m.refs), (None, BTreeMap::from([("HEAD".to_string(), one.clone())])));
        let e = manifest_of(&refs[1..], ObjectFormat::Sha1).unwrap_err();
        assert_eq!((code(&e), exit(e)), (refusal::NOT_SEEDED, 9));
    }

    /// The `fetch` request: the three features, each want, at most
    /// `HAVES_MAX` haves in their order, then `done`, and none of
    /// `NEVER_SENT`; no want, or an id that is not one (a LF in it would
    /// add a line), is refused before anything is sent. The real upload-pack
    /// answers it with a pack that holds the wanted commit and no tag object,
    /// though an annotated tag names that commit.
    #[test]
    fn the_fetch_request_never_asks_tags_depth_or_filters() {
        let id = |n: u32| format!("{n:040x}");
        let wants = vec![id(1), id(2)];
        let haves: Vec<String> = (10..310).map(id).collect();
        let request = fetch_request(&advert(), &wants, &haves).unwrap();
        let lines = decoded(&request);
        let first: Vec<String> = ["command=fetch", "object-format=sha1", "0001", "thin-pack", "ofs-delta", "no-progress"].iter().map(|s| (*s).to_string()).chain([format!("want {}", id(1)), format!("want {}", id(2))]).collect();
        assert_eq!(lines[..8], first[..]);
        let had: Vec<&String> = lines.iter().filter(|l| l.starts_with("have ")).collect();
        assert_eq!((had.len(), had[0].as_str(), had[HAVES_MAX - 1].as_str()), (HAVES_MAX, format!("have {}", id(10)).as_str(), format!("have {}", id(265)).as_str()));
        assert_eq!(lines[lines.len() - 2..], ["done", "0000"]);
        assert_eq!(lines.len(), 8 + HAVES_MAX + 2);
        for word in NEVER_SENT {
            assert!(!request.windows(word.len()).any(|w| w == word.as_bytes()), "{word}");
        }
        assert!(matches!(fetch_request(&advert(), &[], &haves), Err(BridgeError::Config(_))), "nothing to want");
        assert!(matches!(fetch_request(&advert(), &[format!("{}\nfilter blob:none", id(1))], &[]), Err(BridgeError::Config(_))));
        assert!(matches!(fetch_request(&advert(), &wants, &["HEAD".into()]), Err(BridgeError::Config(_))));
        let many: Vec<String> = (0..25_000).map(id).collect();
        let e = fetch_request(&advert(), &many, &[]).unwrap_err();
        assert_eq!((code(&e), exit(e)), (refusal::TOO_LARGE, 9));
        // The real upload-pack: an annotated tag names the wanted commit, and no tag object comes.
        let tmp = tempfile::tempdir().unwrap();
        let vm = tmp.path().join("vm");
        let head = repo(&vm);
        git(&vm, &["tag", "-a", "v1", "-m", "a tag"]);
        let answer = git_io(&vm, &["upload-pack", "--stateless-rpc", "."], &fetch_request(&advert(), std::slice::from_ref(&head), &[]).unwrap(), true);
        let pack = demuxed(&answer, 1 << 20, 4096).unwrap();
        let mac = tmp.path().join("mac.git");
        std::fs::create_dir_all(&mac).unwrap();
        git(&mac, &["init", "-q", "--bare"]);
        git_io(&mac, &["index-pack", "--stdin"], &pack, false);
        let types = git(&mac, &["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"]);
        assert!(types.lines().any(|l| l == format!("{head} commit")) && !types.lines().any(|l| l.ends_with(" tag")), "{types}");
    }

    proptest::proptest! {
        /// A `fetch` answer through the demux in any chunking (a byte a
        /// write, a pkt-line split across writes, all at once) gives the same
        /// pack: band 1's bytes in order, the shallow-info and the progress
        /// left aside.
        #[test]
        fn the_demux_survives_any_chunking(cuts in proptest::collection::vec(1usize..400, 0..40)) {
            let pack: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
            let lines: [(u8, &[u8]); 5] = [(2, b"Enumerating objects: 3\r"), (1, &pack[..1200]), (2, b"Counting objects: 100% (3/3)\n"), (1, &pack[1200..1201]), (1, &pack[1201..])];
            let whole = answer(&["shallow 5967b2b8d96bf7c5bf270ac377c92b51e8b952ea"], &lines, FLUSH_PKT);
            let mut d = Demux::new(Vec::new(), pack.len() as u64);
            let mut at = 0usize;
            for n in cuts.iter().copied().chain(std::iter::once(usize::MAX)) {
                let end = at.saturating_add(n).min(whole.len());
                d.write_all(&whole[at..end]).unwrap();
                at = end;
                if at == whole.len() {
                    break;
                }
            }
            let (got, n) = d.finish().unwrap();
            proptest::prop_assert_eq!(n, pack.len() as u64);
            proptest::prop_assert!(got == pack);
        }
    }

    /// What the VM's git says on band 3, or in an `ERR` line, is
    /// `git_failed` (exit 1): one line, scrubbed (an access key id built
    /// here never shows), control characters blanked, at most `BAND3_MAX`
    /// characters of it kept.
    #[test]
    fn band_3_is_scrubbed() {
        let key = format!("{}{}", "AKIA", "Q7".repeat(8));
        let said = format!("fatal: \x1b[31mbad object\x1b[0m {key}\nremote: {}\n", "x".repeat(1000));
        let body = answer(&[], &[(1, b"PACK"), (3, said.as_bytes())], FLUSH_PKT);
        for chunk in [1, 7, body.len()] {
            let e = demuxed(&body, 1 << 20, chunk).unwrap_err();
            let BridgeError::WorkspaceFailed { code, message } = &e else { panic!("{e:?}") };
            assert_eq!(*code, refusal::GIT_FAILED);
            let kept = message.split_once("the VM's upload-pack failed: ").map(|(_, k)| k).unwrap_or_else(|| panic!("{message}"));
            assert!(kept.chars().count() <= BAND3_MAX && kept.contains("bad object"), "{kept}");
            assert!(!message.contains(&key) && !message.chars().any(char::is_control), "{message:?}");
            assert_eq!(exit(e), 1);
        }
        // An ERR line (git's `not our ref`) before any section, in the advertisement and in an ls-refs answer.
        let err = pkts(&[&format!("ERR upload-pack: not our ref {key}")]);
        for e in [demuxed(&err, 1 << 20, 3).unwrap_err(), parse_advert(&err, ObjectFormat::Sha1).unwrap_err(), parse_ls_refs(&[err.clone(), FLUSH_PKT.to_vec()].concat(), ObjectFormat::Sha1).unwrap_err()] {
            let text = e.to_string();
            assert_eq!(code(&e), refusal::GIT_FAILED, "{text}");
            assert!(text.contains("not our ref") && !text.contains(&key), "{text}");
        }
    }

    /// Band 1 past the cap is `too_large` (exit 9), whatever the chunking;
    /// a pack exactly at the cap passes. Once refused, the demux takes no
    /// more: every write fails, and finishing it is no pack.
    #[test]
    fn a_pack_over_the_cap_is_too_large() {
        let pack = vec![7u8; 1000];
        let body = answer(&["shallow 5967b2b8d96bf7c5bf270ac377c92b51e8b952ea"], &[(1, &pack[..600]), (2, b"progress"), (1, &pack[600..])], FLUSH_PKT);
        assert_eq!(demuxed(&body, 1000, 64).unwrap(), pack);
        for chunk in [1, 64, body.len()] {
            let e = demuxed(&body, 999, chunk).unwrap_err();
            assert!(matches!(&e, BridgeError::WorkspaceRefused { code, message } if *code == refusal::TOO_LARGE && message.contains("box fetch --max-mib")), "{e:?}");
            assert_eq!(exit(e), 9);
        }
        let mut d = Demux::new(Vec::new(), 10);
        assert!(d.write_all(&body).is_err());
        assert!(d.write_all(FLUSH_PKT).is_err(), "nothing more is taken");
        assert!(matches!(d.take_failure(), Some(BridgeError::WorkspaceRefused { .. })));
        assert!(d.finish().is_err());
        assert!(answer_cap(1000) > 1000 && answer_cap(u64::MAX) == u64::MAX);
    }

    /// The client through a transport: an answer cut before its last chunk
    /// is asked once more and its file started again (never the second pack
    /// after the cut first), 0600; one over the cap is `too_large` (exit 9)
    /// and never asked again; a 404 is a VM without `git_http_v1` (exit 7,
    /// `make deploy`); a 403 twice is the token refused (exit 7) after one
    /// re-mint.
    #[tokio::test]
    async fn the_client_starts_a_cut_answer_again_and_reads_its_statuses() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("in.pack");
        let pack: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let whole = answer(&[], &[(1, &pack[..2000]), (1, &pack[2000..])], FLUSH_PKT);
        let (api, t) = (FakeMicrovmApi::new(), target());
        let wants = vec!["a".repeat(40)];
        let canned = Canned::new(vec![(200, whole.clone(), true), (200, whole.clone(), false)]);
        let client = Client { api: &api, tokens: &Tokens, git: &canned, target: &t };
        let advert = client.advertise(ObjectFormat::Sha1).await.unwrap();
        let n = client.fetch_pack(&advert, &wants, &[], &dest, 1 << 20).await.unwrap();
        assert_eq!((n, std::fs::read(&dest).unwrap() == pack, canned.requests()), (pack.len() as u64, true, 2));
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        let canned = Canned::new(vec![(200, whole.clone(), false)]);
        let client = Client { git: &canned, ..client };
        let e = client.fetch_pack(&advert, &wants, &[], &dest, 2999).await.unwrap_err();
        assert_eq!((code(&e), canned.requests()), (refusal::TOO_LARGE, 1));
        assert_eq!(exit(e), 9);
        let canned = Canned::new(vec![(404, Vec::new(), false)]);
        let client = Client { git: &canned, ..client };
        let e = client.ls_refs(&advert).await.unwrap_err();
        assert!(matches!(&e, BridgeError::NoCapability { cap, .. } if *cap == CAP_GIT_HTTP_V1) && e.to_string().contains("make deploy"), "{e:?}");
        assert_eq!(exit(e), 7);
        let canned = Canned::new(vec![(403, Vec::new(), false), (403, Vec::new(), false)]);
        let client = Client { git: &canned, ..client };
        let e = client.ls_refs(&advert).await.unwrap_err();
        assert!(matches!(e, BridgeError::TokenRejected { port: CODE_PORT, status: 403, .. }), "{e:?}");
        assert_eq!((exit(e), canned.requests()), (7, 2));
    }

    /// A transport whose `fetch` answer streams on past the VM's cut, as the
    /// shim's stream ends one (S9 phase 4, F4): a `packfile` section of
    /// band-1 lines of `line` bytes, in reads of `read` bytes, the read that
    /// would pass `GIT_RESPONSE_MAX` dropped and the answer then cut
    /// (`Endpoint`); never past the Mac's cap (`too_large`). Nothing is kept.
    struct Endless {
        line: Vec<u8>,
        read: usize,
        requests: std::sync::atomic::AtomicU32,
    }

    impl GitHttp for Endless {
        async fn info_refs(&self, _: &AgentTarget, _: &AuthToken) -> Result<DpReply<Vec<u8>>, BridgeError> {
            Ok(DpReply::ok(200, sha1_advert()))
        }

        async fn upload_pack<W: Write + Send>(&self, _: &AgentTarget, _: &AuthToken, _: &[u8], sink: &mut W, cap: u64) -> Result<DpReply<u64>, BridgeError> {
            self.requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut head = Vec::new();
            put_pkt(&mut head, b"packfile\n").map_err(BridgeError::Config)?;
            let (mut at, mut sent, mut buf) = (0usize, 0u64, vec![0u8; self.read]);
            loop {
                let mut filled = head.len().min(buf.len());
                buf[..filled].copy_from_slice(&head[..filled]);
                head.drain(..filled);
                while filled < buf.len() {
                    let n = (self.line.len() - at).min(buf.len() - filled);
                    buf[filled..filled + n].copy_from_slice(&self.line[at..at + n]);
                    at = (at + n) % self.line.len();
                    filled += n;
                }
                if sent + buf.len() as u64 > crate::wire::workspace::GIT_RESPONSE_MAX {
                    return Err(BridgeError::Endpoint("the answer was cut before its last chunk".into()));
                }
                if sent + buf.len() as u64 > cap {
                    return Err(BridgeError::WorkspaceRefused { code: refusal::TOO_LARGE, message: "over the cap".into() });
                }
                sink.write_all(&buf)?;
                sent += buf.len() as u64;
            }
        }
    }

    /// A pack as large as the VM's cut (S9 phase 4, F4): with `--max-mib
    /// 1024` the answer is `too_large` (exit 9) after one request, whether
    /// the demux refuses first (git's 65515-byte lines: its `--max-mib`
    /// text) or the answer's cap (999-byte lines), whatever the shim's read;
    /// never a cut answer asked again. A `--max-mib` under the margin is
    /// the demux's own.
    #[tokio::test]
    async fn a_pack_as_large_as_the_vms_cut_is_too_large_at_once() {
        let (api, t) = (FakeMicrovmApi::new(), target());
        let wants = vec!["a".repeat(40)];
        for (data, read) in [(65515usize, 65536usize), (65515, 65000), (999, 65536), (999, 65000)] {
            let mut payload = vec![1u8];
            payload.extend(std::iter::repeat_n(b'p', data));
            let mut line = Vec::new();
            put_pkt(&mut line, &payload).unwrap();
            let git = Endless { line, read, requests: std::sync::atomic::AtomicU32::new(0) };
            let client = Client { api: &api, tokens: &Tokens, git: &git, target: &t };
            let advert = client.advertise(ObjectFormat::Sha1).await.unwrap();
            let e = client.fetch_pack(&advert, &wants, &[], Path::new("/dev/null"), 1024 << 20).await.unwrap_err();
            assert_eq!((code(&e), git.requests.load(std::sync::atomic::Ordering::SeqCst)), (refusal::TOO_LARGE, 1), "{data} {read}: {e:?}");
            if data == 65515 {
                assert!(e.to_string().contains("over 1022.0 MiB"), "{e}");
            }
            assert_eq!(exit(e), 9);
        }
    }

    /// The lead (G1's open point for G2): a `fetch` that wants nothing is
    /// never sent. The VM's http-backend answers one with its head alone,
    /// which the shim turns into a 200 cut before its last chunk (on the
    /// Mac, `BridgeError::Endpoint`), so the request builder refuses it
    /// (`Config`, exit 1) before the client starts an exchange: no request
    /// goes out and no pack file is made. (`codeout::fetch_smart_http` asks
    /// for none: nothing new, or every ref kept out, ends before it.)
    #[tokio::test]
    async fn a_fetch_that_wants_nothing_is_never_sent() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("in.pack");
        let (api, t) = (FakeMicrovmApi::new(), target());
        let canned = Canned::new(Vec::new());
        let client = Client { api: &api, tokens: &Tokens, git: &canned, target: &t };
        let advert = client.advertise(ObjectFormat::Sha1).await.unwrap();
        let e = client.fetch_pack(&advert, &[], &["b".repeat(40)], &dest, 1 << 20).await.unwrap_err();
        assert!(matches!(&e, BridgeError::Config(m) if m.contains("a fetch with nothing to want")), "{e:?}");
        assert_eq!((exit(e), canned.requests(), dest.exists()), (1, 0, false));
    }

    /// The whole client against the real upload-pack (v2, stateless, its
    /// answers written in 1000-byte pieces): a VM repository cloned shallow
    /// from the Mac's, the agent's commits on two branches and a snapshot
    /// ref, a tag. The advertisement, `ls-refs` and the manifest of it;
    /// `fetch` of every ref's commit with the Mac's HEAD for the have (the
    /// shallow VM's shallow-info read and left aside). The thin pack indexes
    /// into the Mac's repository with `--fix-thin`, every wanted commit is
    /// there whole, and no tag came; the same answer a byte a write gives the
    /// same pack.
    #[tokio::test]
    async fn a_real_upload_pack_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let mac = root.join("mac");
        repo(&mac);
        let big: String = (0..2000).map(|i| format!("line {i} of a file large enough to delta\n")).collect();
        std::fs::write(mac.join("big.txt"), &big).unwrap();
        git(&mac, &["add", "big.txt"]);
        git(&mac, &["commit", "-q", "-m", "base"]);
        let base = git(&mac, &["rev-parse", "HEAD"]);
        git(&root, &["clone", "-q", "--depth", "1", &format!("file://{}", mac.display()), "vm"]);
        let vm = root.join("vm");
        std::fs::write(vm.join("big.txt"), big.replace("line 1000 of", "line ONE THOUSAND of")).unwrap();
        git(&vm, &["commit", "-q", "-am", "agent"]);
        let agent = git(&vm, &["rev-parse", "HEAD"]);
        git(&vm, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(vm.join("f.txt"), "f\n").unwrap();
        git(&vm, &["add", "f.txt"]);
        git(&vm, &["commit", "-q", "-m", "feature"]);
        let feature = git(&vm, &["rev-parse", "HEAD"]);
        git(&vm, &["update-ref", "refs/wip/20261018T080000Z-1", &feature]);
        git(&vm, &["tag", "-a", "v1", "-m", "a tag", &agent]);
        git(&vm, &["checkout", "-q", "main"]);
        let (api, t, transport) = (FakeMicrovmApi::new(), target(), UploadPack { repo: vm.clone() });
        let client = Client { api: &api, tokens: &Tokens, git: &transport, target: &t };
        let advert = client.advertise(ObjectFormat::Sha1).await.unwrap();
        let m = manifest_of(&client.ls_refs(&advert).await.unwrap(), advert.object_format).unwrap();
        assert_eq!((m.head.as_str(), m.branch.as_deref()), (agent.as_str(), Some("main")));
        let refs: Vec<(&str, &str)> = m.refs.iter().map(|(r, id)| (r.as_str(), id.as_str())).collect();
        assert_eq!(refs, [("refs/heads/feature", feature.as_str()), ("refs/heads/main", agent.as_str()), ("refs/wip/20261018T080000Z-1", feature.as_str())]);
        let wants: Vec<String> = m.refs.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
        let dest = root.join("in.pack");
        let bytes = client.fetch_pack(&advert, &wants, std::slice::from_ref(&base), &dest, 1 << 20).await.unwrap();
        let pack = std::fs::read(&dest).unwrap();
        assert!(bytes == pack.len() as u64 && pack.starts_with(b"PACK"), "{bytes}");
        git_io(&mac, &["index-pack", "--stdin", "--fix-thin"], &pack, false);
        git(&mac, &["rev-list", "--objects", &agent, &feature, "--not", &base]);
        let types = git(&mac, &["cat-file", "--batch-all-objects", "--batch-check=%(objecttype)"]);
        assert!(!types.lines().any(|t| t == "tag"), "no tag object crossed: {types}");
        let raw = git_io(&vm, &["upload-pack", "--stateless-rpc", "."], &fetch_request(&advert, &wants, std::slice::from_ref(&base)).unwrap(), true);
        assert!(raw.windows(12).any(|w| w == b"shallow-info"), "the shallow VM's answer holds its shallow-info");
        assert_eq!(demuxed(&raw, 1 << 20, 1).unwrap(), demuxed(&raw, 1 << 20, raw.len()).unwrap());
    }
}
