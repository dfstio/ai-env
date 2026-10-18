//! The S8 workspace data plane's shared wire (every feature set; serde
//! only): the seed, code-out, transcript and settings requests and replies
//! the Mac (`bridge::workspace`, `bridge::codeout`, `bridge::dataplane`) and
//! the shim (`shim::code`, `shim::wshelper`) exchange, their refusal codes
//! and statuses, and the validators both sides apply (a workspace path, a
//! transcript's rel). Frozen in S8 phase 0 (C2); S8 wave 1 builds both ends
//! (W3 the shim's routes and the agent's helper, W4 the Mac's client).
//!
//! The routes, each behind the peer guard and the bearer, served only by a
//! shim that names [`CAP_WORKSPACE_V1`](crate::wire::frame::CAP_WORKSPACE_V1)
//! (an older one answers 404):
//! * the code port ([`CODE_PORT`]): `GET /seed?path=` answers the
//!   workspace's [`SeedState`]; `PUT /seed` ([`SeedQuery`]) takes a
//!   [`SeedManifest`] line, then the pack (`Content-Length` required, at most
//!   [`SEED_BODY_MAX`]), and answers a [`SeedReply`]; `POST /codeout` takes a
//!   [`CodeoutRequest`] (at most [`CODEOUT_REQUEST_MAX`]) and answers a
//!   [`CodeoutManifest`] line, then the pack, or 204 when nothing is new;
//! * the app port ([`APP_PORT`], `app_bearer`): `GET /transcript?rel=`
//!   answers a [`TranscriptStat`]; `GET /settings?path=` answers a
//!   [`SettingsCapture`]. (S8's `PUT /transcript`, the Mac's mirror sent up
//!   at a resume, went at the S3 cut-over: S9 restores a chat from S3.)
//!
//! Statuses: 201 (cloned, updated or replaced), 200 (up to date, a state, a
//! stat, a capture, a code-out pack), 204
//! (nothing new to code out). A refusal is a [`WsRefusal`] body with its
//! code's status ([`refusal_status`]: 400, 409, 413, 422, 500, 503 or 504);
//! a body without `Content-Length` is 411 `bad_request`.
//!
//! A body that carries a pack starts with one line of compact JSON (its
//! manifest), then the raw pack ([`write_framed`], [`read_head_line`]); the
//! agent's helper (`ai-env shim-io`) answers the root shim the same way, its
//! first stdout line a [`HelperHead`]. A path crosses in its VM form only
//! (UTF-8, absolute, NFC: [`vm_path_of`], [`vm_path_check`]): the VM never
//! normalises one, it refuses it. A ref or an object id is checked before
//! any git run sees it ([`is_ref_name`], [`branch_check`], [`ObjectFormat`]).
//!
//! S9 (frozen in S9 phase 0; plans/s9-contracts.md §1) adds, each served
//! only by a shim that names its capability: git smart-HTTP on the code
//! port (`CAP_GIT_HTTP_V1`: [`GIT_INFO_REFS_ROUTE`] and
//! [`GIT_UPLOAD_PACK_ROUTE`], upload-pack only, [`GIT_RECEIVE_PACK_ROUTE`]
//! 403), and the transcript store's transfers on the app port
//! (`CAP_TRANSCRIPT_S3_V1`): the extended stat ([`StatQuery`]),
//! [`TranscriptPush`], [`TranscriptPull`], [`ViewQuery`] and
//! [`TranscriptTail`], their presigned URLs `wire::s3::PresignedUrl`s whose
//! keys must fit the bytes they move. A helper whose reply can pass
//! [`HEAD_LINE_MAX`] answers a [`JsonPayloadReply`] head, then the reply.
use crate::wire::mirror::mirror_key;
use crate::wire::redact::scrub;
use crate::wire::s3::{is_account_id, proxy_check, PresignedUrl, S3Key, PULL_PARTS_MAX, PUSH_MAX, SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT, SIGNED_HEADERS_TAIL};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};
use unicode_normalization::{is_nfc, UnicodeNormalization};

// ---- ports, routes and limits ------------------------------------------------------------

/// The image's code port (its ENTRYPOINT's `--code-port`): `/seed`, `/codeout`.
pub const CODE_PORT: u16 = 9418;
/// The image's app port (`--app-port`): `/transcript`, `/settings`.
pub const APP_PORT: u16 = 8080;
/// `GET` (the state) and `PUT` (a seed) on [`CODE_PORT`].
pub const SEED_ROUTE: &str = "/seed";
/// `POST` on [`CODE_PORT`].
pub const CODEOUT_ROUTE: &str = "/codeout";
/// `GET` (the stat; S9's extended one too) on [`APP_PORT`].
pub const TRANSCRIPT_ROUTE: &str = "/transcript";
/// `GET` on [`APP_PORT`].
pub const SETTINGS_ROUTE: &str = "/settings";

/// S9: the VM's one repository on [`CODE_PORT`] (`CAP_GIT_HTTP_V1`), its routes literal.
pub const GIT_REPO_PREFIX: &str = "/workspace.git";
/// `GET` with exactly [`GIT_UPLOAD_PACK_QUERY`]: the advertisement.
pub const GIT_INFO_REFS_ROUTE: &str = "/workspace.git/info/refs";
/// `POST`: one upload-pack request (no query).
pub const GIT_UPLOAD_PACK_ROUTE: &str = "/workspace.git/git-upload-pack";
/// Any method: 403 [`GIT_RECEIVE_PACK_REFUSAL`], no helper started.
pub const GIT_RECEIVE_PACK_ROUTE: &str = "/workspace.git/git-receive-pack";
/// S9: `POST` on [`APP_PORT`] (`CAP_TRANSCRIPT_S3_V1`): a [`TranscriptPush`].
pub const TRANSCRIPT_PUSH_ROUTE: &str = "/transcript/push";
/// `POST`: a [`TranscriptPull`].
pub const TRANSCRIPT_PULL_ROUTE: &str = "/transcript/pull";
/// `GET` with a [`ViewQuery`]: a `wire::view::TranscriptViewReply`.
pub const TRANSCRIPT_VIEW_ROUTE: &str = "/transcript/view";
/// `POST`: a [`TranscriptTail`].
pub const TRANSCRIPT_TAIL_ROUTE: &str = "/transcript/tail";

/// The one query of [`GIT_INFO_REFS_ROUTE`].
pub const GIT_UPLOAD_PACK_QUERY: &str = "service=git-upload-pack";
/// receive-pack's: 403.
pub const GIT_RECEIVE_PACK_QUERY: &str = "service=git-receive-pack";
/// The CGI's `PATH_INFO` of each route (never taken from the URL).
pub const GIT_PATH_INFO_REFS: &str = "/info/refs";
pub const GIT_PATH_INFO_UPLOAD_PACK: &str = "/git-upload-pack";
/// The advertisement's, a request's and a result's `Content-Type`.
pub const GIT_ADVERTISEMENT_TYPE: &str = "application/x-git-upload-pack-advertisement";
pub const GIT_UPLOAD_PACK_REQUEST_TYPE: &str = "application/x-git-upload-pack-request";
pub const GIT_UPLOAD_PACK_RESULT_TYPE: &str = "application/x-git-upload-pack-result";
/// The `Content-Encoding`s a request may carry (none, or one of these).
pub const GIT_CONTENT_ENCODINGS: [&str; 2] = ["gzip", "x-gzip"];
/// The `Git-Protocol` values a request may carry (none, or one of these).
pub const GIT_PROTOCOLS: [&str; 3] = ["version=0", "version=1", "version=2"];
/// What the Mac's client asks (M5).
pub const GIT_PROTOCOL_V2: &str = "version=2";
/// The CGI's headers the root shim passes on (lowercase; compared ignoring ASCII case): no other.
pub const GIT_CGI_HEADERS: [&str; 4] = ["content-type", "cache-control", "expires", "pragma"];
/// The CGI's environment beside `GitRun::vm`'s own: an allowlist (never a bearer, a cookie or an `x-aws-*` header).
pub const GIT_CGI_ENV: [&str; 10] = ["GIT_PROJECT_ROOT", "GIT_HTTP_EXPORT_ALL", "PATH_INFO", "REQUEST_METHOD", "QUERY_STRING", "CONTENT_TYPE", "CONTENT_LENGTH", "HTTP_CONTENT_ENCODING", "HTTP_GIT_PROTOCOL", "REMOTE_ADDR"];
/// `-c` overrides on http-backend's command line (they beat the agent's repository config).
pub const GIT_CGI_OVERRIDES: [&str; 3] = ["http.receivepack=false", "http.getanyfile=false", "http.uploadpack=true"];
/// What both ports answer (404) for a path no route serves.
pub const NO_SUCH_ROUTE: &str = "ai-env: no such route\n";
/// The 403 of receive-pack, in either form.
pub const GIT_RECEIVE_PACK_REFUSAL: &str = "ai-env: receive-pack is refused: the VM's repository is never written through the code port\n";

const MIB: u64 = 1024 * 1024;
/// The largest `PUT /seed` body the shim takes, its manifest line included
/// (`[seed]` caps a seed at `SeedCfg::MIB_MAX` MiB), and the largest
/// `max_bytes` a code-out asks for. The shim counts the bytes itself: a
/// streamed body is never buffered.
pub const SEED_BODY_MAX: u64 = 1024 * MIB;
/// The largest `POST /codeout` body (a [`CodeoutRequest`]).
pub const CODEOUT_REQUEST_MAX: usize = 64 * 1024;
/// The largest settings file a capture carries the text of.
pub const SETTINGS_FILE_MAX: usize = 256 * 1024;
/// The most object ids a [`CodeoutRequest`] names as the Mac's (and the
/// most boundary commits a [`SeedManifest`] lists).
pub const HAVES_MAX: usize = 256;
/// The longest head line, its `\n` included: a manifest, a helper's head.
pub const HEAD_LINE_MAX: usize = 64 * 1024;
/// The longest VM path, in bytes (Linux's `PATH_MAX`).
pub const VM_PATH_MAX: usize = 4096;
/// The longest project slug of a transcript rel.
pub const SLUG_MAX: usize = 255;
/// The most directories a transcript rel names below `<uuid>/`: the S2
/// seeder's `MAX_SUBTREE_DEPTH`, so every file it would copy and the mirror
/// accepts can go up.
pub const TRANSCRIPT_DIRS_MAX: usize = 8;
/// The longest component of a transcript rel (Linux's `NAME_MAX`).
pub const SEGMENT_MAX: usize = 255;
/// The longest transcript rel, in bytes.
pub const REL_MAX: usize = 4096;
/// The longest full ref name a manifest may carry.
pub const REF_NAME_MAX: usize = 1024;
/// S9: an upload-pack request body (ours are 15 KiB at most).
pub const GIT_REQUEST_MAX: u64 = MIB;
/// One CGI response body.
pub const GIT_RESPONSE_MAX: u64 = 1024 * MIB;
/// The CGI's header block.
pub const GIT_CGI_HEAD_MAX: usize = 16 * 1024;
/// CGI runs at once (the next is 409 `busy` at once).
pub const GIT_CGI_MAX: usize = 2;
/// A push, pull, or tail body: a pull's `PULL_PARTS_MAX` parts of at most
/// `PRESIGNED_URL_MAX` bytes each, their JSON and a rel fit.
pub const TRANSFER_REQUEST_MAX: usize = 640 * 1024;
/// Push, pull and tail runs at once.
pub const TRANSFERS_MAX: usize = 4;
/// The parts of one pull, summed.
pub const PULL_MAX: u64 = PUSH_MAX;
/// The files an extended stat lists.
pub const SUBTREE_FILES_MAX: usize = 256;
/// Their bytes, hashed.
pub const SUBTREE_BYTES_MAX: u64 = 256 * MIB;
/// A helper's JSON payload ([`JsonPayloadReply`]), the Mac's `dataplane::MAX_JSON`: a view's reply
/// (`VIEW_FILE_MAX` of text escaped at most 6 bytes per byte, plus its capped fields: under 1.6 MiB),
/// a subtree stat (`SUBTREE_FILES_MAX` rels of at most `REL_MAX` bytes: under 1.1 MiB).
pub const JSON_PAYLOAD_MAX: usize = 2 * 1024 * 1024;

/// What the agent's helper may take per operation in the VM (plan §6): the
/// shim ends its process group past it (504 `timeout`). The Mac's own wait
/// adds the transfer (`bridge::dataplane::request_timeout`).
pub mod budget {
    use std::time::Duration;

    /// `GET /seed`: the state of the checkout.
    pub const SEED_STATE: Duration = Duration::from_secs(30);
    /// `PUT /seed` of a first seed (`clone`).
    pub const SEED_CLONE: Duration = Duration::from_secs(600);
    /// `PUT /seed` of an `update` or a `replace`.
    pub const SEED_UPDATE: Duration = Duration::from_secs(180);
    /// `POST /codeout`: the snapshot, then the pack.
    pub const CODEOUT: Duration = Duration::from_secs(120);
    /// The `/suspend` hook's snapshot (after `freeze()`, before the sockets close).
    pub const SUSPEND_SNAPSHOT: Duration = Duration::from_secs(8);
    /// `GET /transcript` (S8's stat and S9's extended one).
    pub const TRANSCRIPT: Duration = Duration::from_secs(60);
    /// `GET /settings`.
    pub const SETTINGS: Duration = Duration::from_secs(10);
    /// How long a request waits for the workspace (one seed, code-out or
    /// snapshot at a time) before it is refused with 409 `busy`.
    pub const BUSY_WAIT: Duration = Duration::from_secs(30);
    /// S9: `GET` info/refs, the whole stream.
    pub const GIT_ADVERTISE: Duration = Duration::from_secs(30);
    /// `POST` git-upload-pack, the whole stream.
    pub const GIT_UPLOAD_PACK: Duration = Duration::from_secs(600);
    /// A push, plus `asagent::transfer(len)`.
    pub const TRANSCRIPT_PUSH: Duration = Duration::from_secs(60);
    /// A pull, plus `asagent::transfer(sum of the parts)`.
    pub const TRANSCRIPT_PULL: Duration = Duration::from_secs(60);
    /// The view.
    pub const TRANSCRIPT_VIEW: Duration = Duration::from_secs(30);
    /// One tail push at `/suspend` or `/terminate`.
    pub const TRANSCRIPT_TAIL: Duration = Duration::from_secs(8);
}

// ---- refusals ----------------------------------------------------------------------------

/// The codes of a [`WsRefusal`], each with its status ([`refusal_status`]).
/// A code names what happened, never a value.
pub mod refusal {
    /// 400: a path, rel, query or body the shim cannot take (not NFC, a `..`, a bad mode).
    pub const BAD_REQUEST: &str = "bad_request";
    /// 409: a component of the path is a symlink (the agent planted one; T8.6).
    pub const SYMLINK_COMPONENT: &str = "symlink_component";
    /// 409: a non-empty directory that is no seed of this shim's is at the path.
    pub const PATH_OCCUPIED: &str = "path_occupied";
    /// 409: the path is not under the agent's home: the agent cannot create it.
    pub const NOT_CREATABLE: &str = "not_creatable";
    /// 409: the VM was seeded at another path (one workspace per VM).
    pub const OTHER_WORKSPACE: &str = "other_workspace";
    /// 409: the VM's checkout has changes of its own (D3 keeps it).
    pub const DIRTY: &str = "dirty";
    /// 409: the VM's tip is not an ancestor of the Mac's head (D3 keeps it).
    pub const DIVERGED: &str = "diverged";
    /// 409: the tip is not the `expect` the Mac read (it moved in between).
    pub const CHANGED: &str = "changed";
    /// 409: a `replace` of a VM that changed since its seed.
    pub const NOT_PRISTINE: &str = "not_pristine";
    /// 409: another seed, code-out or snapshot held the workspace past `budget::BUSY_WAIT`.
    pub const BUSY: &str = "busy";
    /// 422: the pack does not index, or the manifest line does not parse.
    pub const BAD_PACK: &str = "bad_pack";
    /// 422: an update's thin pack needs objects the VM lacks.
    pub const MISSING_PREREQUISITES: &str = "missing_prerequisites";
    /// 422: a manifest names a ref outside its set, or one whose commit the pack lacks.
    pub const BAD_REFS: &str = "bad_refs";
    /// 413: a body over its cap, or a code-out pack over the request's `max_bytes`.
    pub const TOO_LARGE: &str = "too_large";
    /// 409: a code-out or a snapshot of a VM never seeded.
    pub const NOT_SEEDED: &str = "not_seeded";
    /// 500: git failed in the VM (the message holds its last stderr lines, scrubbed).
    pub const GIT_FAILED: &str = "git_failed";
    /// 504: the helper outlived its budget; its process group was ended.
    pub const TIMEOUT: &str = "timeout";
    /// 503: the shim is stopping (a suspend, a terminate): nothing new starts.
    pub const DRAINING: &str = "draining";
    /// 500 (S9): the transfer to or from S3 did not happen (curl reported no
    /// HTTP status: the proxy, a connection; or a helper failed).
    pub const TRANSFER_FAILED: &str = "transfer_failed";
    /// Every code above.
    pub const ALL: [&str; 19] = [
        BAD_REQUEST,
        SYMLINK_COMPONENT,
        PATH_OCCUPIED,
        NOT_CREATABLE,
        OTHER_WORKSPACE,
        DIRTY,
        DIVERGED,
        CHANGED,
        NOT_PRISTINE,
        BUSY,
        BAD_PACK,
        MISSING_PREREQUISITES,
        BAD_REFS,
        TOO_LARGE,
        NOT_SEEDED,
        GIT_FAILED,
        TIMEOUT,
        DRAINING,
        TRANSFER_FAILED,
    ];
}

/// The status a refusal of `code` is answered with: 400 `bad_request`; 409
/// for what the workspace's state refuses; 413 `too_large`; 422 for a pack
/// or refs the VM cannot take; 500 `git_failed`; 503 `draining`; 504
/// `timeout`. An unknown code is 500. (A body without `Content-Length` is
/// 411 with `bad_request`.)
#[must_use]
pub fn refusal_status(code: &str) -> u16 {
    use refusal::*;
    match code {
        BAD_REQUEST => 400,
        SYMLINK_COMPONENT | PATH_OCCUPIED | NOT_CREATABLE | OTHER_WORKSPACE | DIRTY | DIVERGED | CHANGED | NOT_PRISTINE | BUSY | NOT_SEEDED => 409,
        TOO_LARGE => 413,
        BAD_PACK | MISSING_PREREQUISITES | BAD_REFS => 422,
        TRANSFER_FAILED => 500,
        DRAINING => 503,
        TIMEOUT => 504,
        _ => 500,
    }
}

/// `code` as the constant of [`refusal::ALL`] it equals (the bridge's
/// errors carry a `&'static str`); `None` for a code this build does not know.
#[must_use]
pub fn known_refusal(code: &str) -> Option<&'static str> {
    refusal::ALL.iter().copied().find(|c| *c == code)
}

/// A refusal: the body of every 4xx and 5xx a workspace route answers, and
/// a helper's head when its op refused ([`HelperHead`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsRefusal {
    /// One of [`refusal::ALL`].
    pub code: String,
    /// One line naming the path, ref or rule, never a value: scrubbed, at
    /// most [`WsRefusal::MESSAGE_MAX`] characters ([`WsRefusal::new`]).
    pub message: String,
    /// The workspace's state when the refusal is about it (`dirty`,
    /// `diverged`, `changed`, `not_pristine`, `other_workspace`), so the Mac
    /// can report what the VM keeps without a second `GET /seed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SeedState>,
    /// A size the refusal is about: the body or the pack over its cap
    /// (`too_large`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

impl WsRefusal {
    /// The longest message, in characters.
    pub const MESSAGE_MAX: usize = 300;

    /// A refusal of `code` with `message` made one line (lines joined by
    /// ` | `, control characters blanked), scrubbed and cut to
    /// [`Self::MESSAGE_MAX`] characters.
    #[must_use]
    pub fn new(code: &str, message: &str) -> WsRefusal {
        WsRefusal { code: code.to_string(), message: one_line(message, Self::MESSAGE_MAX), state: None, size: None }
    }

    /// With the workspace's state.
    #[must_use]
    pub fn with_state(mut self, state: SeedState) -> WsRefusal {
        self.state = Some(state);
        self
    }

    /// With the size it is about.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> WsRefusal {
        self.size = Some(size);
        self
    }

    /// The status it is answered with ([`refusal_status`]).
    #[must_use]
    pub fn status(&self) -> u16 {
        refusal_status(&self.code)
    }
}

/// `text`'s lines joined by ` | `, control characters blanked, scrubbed,
/// at most `max` characters (an ellipsis last when cut).
fn one_line(text: &str, max: usize) -> String {
    let joined = text.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
    let clean: String = scrub(&joined).chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if clean.chars().count() <= max {
        return clean;
    }
    let mut out: String = clean.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

// ---- validators --------------------------------------------------------------------------
//
// Each `Err` is a predicate naming the rule ("is not absolute"), to follow
// the caller's subject ("the workspace path …"); it never quotes the value.

/// Is `s` a session id in the session picker's shape: 36 characters, hex
/// digits (either case) in the 8-4-4-4-12 groups, `-` at offsets 8, 13, 18
/// and 23. `bridge::registry::is_uuid` is this check, so `..`, `/` and empty
/// strings never reach a path on either side.
#[must_use]
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// `s` in Unicode NFC (the form the Mac sends; macOS hands out paths in
/// either form, the extension's slug uses NFC).
#[must_use]
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// A VM path (a workspace's, a settings capture's): non-empty, absolute, at
/// most [`VM_PATH_MAX`] bytes, no NUL, in NFC (`unicode_normalization::is_nfc`;
/// the Mac normalises, the VM refuses), and every component non-empty and
/// neither `.` nor `..` (one spelling per path: no `//`, no trailing `/`).
/// `/` itself passes (the shim then refuses it as outside the agent's home).
pub fn vm_path_check(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("is empty".into());
    }
    if path.len() > VM_PATH_MAX {
        return Err(format!("is {} bytes long (at most {VM_PATH_MAX})", path.len()));
    }
    if !path.starts_with('/') {
        return Err("is not absolute".into());
    }
    if path.contains('\0') {
        return Err("holds a NUL byte".into());
    }
    if !is_nfc(path) {
        return Err("is not in Unicode NFC (the Mac sends every path NFC-normalised)".into());
    }
    if path == "/" {
        return Ok(());
    }
    for component in path[1..].split('/') {
        match component {
            "" => return Err("has an empty component (`//` or a trailing `/`)".into()),
            "." | ".." => return Err("has a `.` or `..` component".into()),
            _ => {}
        }
    }
    Ok(())
}

/// The VM form of a Mac path (the only form sent to the VM, as the seed's
/// path and as the spawn's cwd): UTF-8, NFC-normalised, then
/// [`vm_path_check`]ed. The caller passes the canonical path.
pub fn vm_path_of(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("is not UTF-8")?;
    let vm = nfc(text);
    vm_path_check(&vm)?;
    Ok(vm)
}

/// The projects root a rel is checked under with the mirror's own rules: any
/// absolute directory, since `mirror_key` is lexical.
const MIRROR_PROBE_ROOT: &str = "/projects";

/// A transcript's path under the projects directory, as `/transcript?rel=`
/// carries it: `<slug>/<uuid>.jsonl`, or `<slug>/<uuid>/<sub…>` with at least
/// two components below `<uuid>/` (the mirror writes nothing at one). The
/// slug is `[A-Za-z0-9_-]{1,255}` (the extension's slug alphabet, and the `_`
/// of a `CLAUDE_CODE_PROJECT_DIR_NAME` the CLI honours: `wire::slug::override_dir_name`),
/// the uuid passes [`is_uuid`], each sub-component is `[A-Za-z0-9._-]+`, at most
/// [`SEGMENT_MAX`] bytes and not starting with `.`, at most
/// [`TRANSCRIPT_DIRS_MAX`] directories deep, the last one ending in `.jsonl`
/// or `.json`; at most [`REL_MAX`] bytes. And `wire::mirror::mirror_key`
/// must give back exactly these parts: the rel is a path the transcript
/// mirror itself writes.
pub fn transcript_rel_check(rel: &str) -> Result<(), String> {
    if rel.is_empty() || rel.len() > REL_MAX {
        return Err(format!("is {} bytes long (1 to {REL_MAX})", rel.len()));
    }
    let segs: Vec<&str> = rel.split('/').collect();
    let slug = segs[0];
    if slug.is_empty() || slug.len() > SLUG_MAX || !slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(format!("does not start with a project slug of [A-Za-z0-9_-]{{1,{SLUG_MAX}}}"));
    }
    let (session, sub) = match segs.len() {
        1 => return Err("names no transcript below its slug".into()),
        2 => (segs[1].strip_suffix(".jsonl").ok_or("names no <uuid>.jsonl below its slug")?, None),
        _ => (segs[1], Some(&segs[2..])),
    };
    if !is_uuid(session) {
        return Err("names no session id (a uuid) below its slug".into());
    }
    if let Some(sub) = sub {
        if sub.len() > TRANSCRIPT_DIRS_MAX + 1 {
            return Err(format!("is nested deeper than {TRANSCRIPT_DIRS_MAX} directories below the session"));
        }
        let bad = |s: &&str| s.is_empty() || s.len() > SEGMENT_MAX || s.starts_with('.') || !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if sub.iter().any(bad) {
            return Err(format!("has a component below the session that is not [A-Za-z0-9._-]{{1,{SEGMENT_MAX}}} without a leading `.`"));
        }
        if !sub.last().is_some_and(|l| l.ends_with(".jsonl") || l.ends_with(".json")) {
            return Err("does not end in .jsonl or .json".into());
        }
    }
    let key = mirror_key(MIRROR_PROBE_ROOT, &format!("{MIRROR_PROBE_ROOT}/{rel}")).ok_or("is not a path the transcript mirror writes (one component below the session is none)")?;
    let subpath = sub.map(|s| {
        let joined = s.join("/");
        joined.strip_suffix(".jsonl").map_or_else(|| joined.clone(), str::to_string)
    });
    if key.project_key != slug || key.session_id != session || key.subpath != subpath {
        return Err("is not read back by the transcript mirror's rules as the same transcript".into());
    }
    Ok(())
}

/// A git repository's object format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    /// As git names it (`git init --object-format=`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ObjectFormat::Sha1 => "sha1",
            ObjectFormat::Sha256 => "sha256",
        }
    }

    /// The hex digits of one of its object ids.
    #[must_use]
    pub fn hex_len(self) -> usize {
        match self {
            ObjectFormat::Sha1 => 40,
            ObjectFormat::Sha256 => 64,
        }
    }

    /// The format whose object ids look like `id` (lowercase hex of 40 or 64
    /// digits); `None` for anything else (an abbreviation, a ref name, upper case).
    #[must_use]
    pub fn of_id(id: &str) -> Option<ObjectFormat> {
        let hex = id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        match id.len() {
            40 if hex => Some(ObjectFormat::Sha1),
            64 if hex => Some(ObjectFormat::Sha256),
            _ => None,
        }
    }

    /// Is `id` one of its object ids?
    #[must_use]
    pub fn is_id(self, id: &str) -> bool {
        ObjectFormat::of_id(id) == Some(self)
    }
}

/// Is `name` a ref name git takes (`git check-ref-format`): at most
/// [`REF_NAME_MAX`] bytes, not `@`, every `/`-separated component non-empty,
/// not starting with `.` and not ending with `.lock`, no `..` or `@{`, no
/// ASCII control character, space, `~`, `^`, `:`, `?`, `*`, `[` or `\`, not
/// ending with `.`. Callers pass full names (`refs/heads/dev`, `HEAD`).
#[must_use]
pub fn is_ref_name(name: &str) -> bool {
    if name.is_empty() || name.len() > REF_NAME_MAX || name == "@" || name.ends_with('.') || name.contains("..") || name.contains("@{") {
        return false;
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f || matches!(b, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')) {
        return false;
    }
    name.split('/').all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
}

/// A branch name (`--branch`, a manifest's `branch`): `refs/heads/<name>`
/// passes [`is_ref_name`], and the name is neither `HEAD` nor `@` (git's
/// names for the checkout) and does not start with `-` (git would read it as
/// an option).
pub fn branch_check(name: &str) -> Result<(), String> {
    if name == "HEAD" || name == "@" || name.starts_with('-') || !is_ref_name(&format!("{HEADS_PREFIX}{name}")) {
        return Err("is not a branch name git takes (git check-ref-format --branch)".into());
    }
    Ok(())
}

/// Exactly one of a branch (checked) and `detached`.
fn one_head(branch: Option<&str>, detached: bool) -> Result<(), String> {
    match (branch, detached) {
        (Some(b), false) => branch_check(b).map_err(|e| format!("the branch {e}")),
        (None, true) => Ok(()),
        (Some(_), true) => Err("names both a branch and `detached`".into()),
        (None, false) => Err("names neither a branch nor `detached`".into()),
    }
}

// ---- refs ----------------------------------------------------------------------------------

/// The prefix of a branch.
pub const HEADS_PREFIX: &str = "refs/heads/";
/// The VM's ref at the seeded commit (the boundary its `.git/shallow` names
/// after a first seed, D7).
pub const SEED_REF: &str = "refs/ai-env/seed";
/// The VM's ref at the seeded WIP commit (D2), when the seed carried one.
pub const SEED_WIP_REF: &str = "refs/ai-env/seed-wip";
/// The prefix of the VM's snapshots of its uncommitted work (L6):
/// `refs/wip/<UTC time>-<n>`, the newest `[seed].keep_wip_refs` kept.
pub const WIP_REF_PREFIX: &str = "refs/wip/";

// ---- queries -------------------------------------------------------------------------------

/// `?path=`: `GET /seed`, `GET /settings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathQuery {
    /// The workspace's VM path ([`vm_path_check`]).
    pub path: String,
}

impl PathQuery {
    /// The query's pairs, for `bridge::vm::health::endpoint_url_query`.
    #[must_use]
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        vec![("path", self.path.clone())]
    }
}

/// `?rel=`: `GET /transcript` (S8's stat).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelQuery {
    /// The transcript's path under the projects directory ([`transcript_rel_check`]).
    pub rel: String,
}

impl RelQuery {
    /// The query's pairs.
    #[must_use]
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        vec![("rel", self.rel.clone())]
    }
}

/// How a `PUT /seed` changes the VM's checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedMode {
    /// The first seed: `git init`, the pack, the refs, the checkout; the WIP
    /// applied uncommitted. No origin ever exists.
    Clone,
    /// D3: a clean VM whose tip is an ancestor of the Mac's head is
    /// fast-forwarded (a thin pack of what it lacks), then the new WIP applied.
    Update,
    /// `box seed --replace`: a VM unchanged since its seed is checked out anew.
    Replace,
}

impl SeedMode {
    /// As the query spells it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SeedMode::Clone => "clone",
            SeedMode::Update => "update",
            SeedMode::Replace => "replace",
        }
    }

    /// The helper's budget for it.
    #[must_use]
    pub fn budget(self) -> Duration {
        match self {
            SeedMode::Clone => budget::SEED_CLONE,
            SeedMode::Update | SeedMode::Replace => budget::SEED_UPDATE,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// `PUT /seed?path=&mode=&branch=|detached=true&expect=`: where, how, which
/// head, and (an update or a replace) the tip the Mac read in `GET /seed`,
/// which the shim compares under its lock (409 `changed` when it moved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedQuery {
    pub path: String,
    pub mode: SeedMode,
    /// The branch to check out; or `detached`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub detached: bool,
    /// The VM's tip the Mac decided on: required by `update` and `replace`,
    /// refused with `clone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
}

impl SeedQuery {
    /// The query's rules: a VM path, exactly one of a branch and `detached`,
    /// `expect` an object id exactly when the mode is not `clone`.
    pub fn check(&self) -> Result<(), String> {
        vm_path_check(&self.path).map_err(|e| format!("the path {e}"))?;
        one_head(self.branch.as_deref(), self.detached)?;
        match (self.mode, self.expect.as_deref()) {
            (SeedMode::Clone, None) => Ok(()),
            (SeedMode::Clone, Some(_)) => Err("a clone expects no tip (expect is for update and replace)".into()),
            (mode, None) => Err(format!("{} needs expect (the tip GET /seed answered)", mode.name())),
            (_, Some(tip)) if ObjectFormat::of_id(tip).is_none() => Err("expect is not an object id".into()),
            _ => Ok(()),
        }
    }

    /// The query's pairs, in this order (`detached=true` only when set).
    #[must_use]
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("path", self.path.clone()), ("mode", self.mode.name().to_string())];
        if let Some(b) = &self.branch {
            out.push(("branch", b.clone()));
        }
        if self.detached {
            out.push(("detached", "true".to_string()));
        }
        if let Some(e) = &self.expect {
            out.push(("expect", e.clone()));
        }
        out
    }
}

// ---- the seed ------------------------------------------------------------------------------

/// The line before the pack in a `PUT /seed` body (D7: a shallow pack, never
/// a bundle): what the pack holds and which refs the VM sets from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedManifest {
    /// [`SeedManifest::V`].
    pub v: u8,
    pub object_format: ObjectFormat,
    /// The branch to check out (the Mac's, or `--branch`); or `detached`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub detached: bool,
    /// The commit to check out: the Mac's head (M).
    pub head: String,
    /// The WIP commit (D2: tracked changes and the vetted untracked files,
    /// its tree the worktree to leave), when the workspace is dirty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip: Option<String>,
    /// The index commit (its tree the index to leave), when the index differs
    /// from the head's tree; only with a `wip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    /// The commits the VM's `.git/shallow` gains with this seed: exactly
    /// `[head]` for a `clone` or a `replace` (no history crosses); for an
    /// `update`, the pack's commits whose parents the VM lacks (a merge of a
    /// branch older than the seeded commit), usually none; at most
    /// [`HAVES_MAX`] ([`SeedManifest::check_for`]).
    #[serde(default)]
    pub shallow: Vec<String>,
    /// Every ref the VM sets from this seed, by full name, to its commit:
    /// exactly [`SeedManifest::expected_refs`].
    pub refs: BTreeMap<String, String>,
}

impl SeedManifest {
    /// The manifest version this build writes and reads.
    pub const V: u8 = 1;

    /// The refs a seed of this head sets: `refs/heads/<branch>` (unless
    /// detached) and [`SEED_REF`] at the head, [`SEED_WIP_REF`] at the WIP.
    #[must_use]
    pub fn expected_refs(&self) -> BTreeMap<String, String> {
        let mut refs = BTreeMap::new();
        if let Some(b) = &self.branch {
            refs.insert(format!("{HEADS_PREFIX}{b}"), self.head.clone());
        }
        refs.insert(SEED_REF.to_string(), self.head.clone());
        if let Some(w) = &self.wip {
            refs.insert(SEED_WIP_REF.to_string(), w.clone());
        }
        refs
    }

    /// The manifest's rules: version [`Self::V`], one head (a branch git
    /// takes, or detached), every id of the object format, an `index` only
    /// with a `wip`, at most [`HAVES_MAX`] shallow commits, and `refs`
    /// exactly [`Self::expected_refs`]. The helper runs it before any git run
    /// (422 `bad_refs` or `bad_pack`).
    pub fn check(&self) -> Result<(), String> {
        if self.v != Self::V {
            return Err(format!("is manifest v{} (this side reads v{})", self.v, Self::V));
        }
        one_head(self.branch.as_deref(), self.detached)?;
        let format = self.object_format;
        let id = |what: &str, s: &str| if format.is_id(s) { Ok(()) } else { Err(format!("has a {what} that is not a {} object id", format.name())) };
        id("head", &self.head)?;
        if let Some(w) = &self.wip {
            id("wip", w)?;
        }
        if let Some(i) = &self.index {
            id("index", i)?;
            if self.wip.is_none() {
                return Err("has an index commit but no wip".into());
            }
        }
        if self.shallow.len() > HAVES_MAX {
            return Err(format!("lists {} shallow commits (at most {HAVES_MAX})", self.shallow.len()));
        }
        for s in &self.shallow {
            id("shallow commit", s)?;
        }
        if self.refs != self.expected_refs() {
            return Err(format!("has refs other than exactly the branch and {SEED_REF} at the head and {SEED_WIP_REF} at the wip"));
        }
        Ok(())
    }

    /// [`Self::check`] and [`SeedQuery::check`], then the manifest against
    /// the `PUT /seed` query it came with: the same head (`branch`,
    /// `detached`), and the shallow boundary its mode needs (D7). A `clone`
    /// or a `replace` lists exactly `[head]`: its pack holds the head's commit
    /// and tree, never their history, so the VM's `.git/shallow` must mark the
    /// head or git would take the history-less clone for a complete one. An
    /// `update`'s thin pack carries the commits from the VM's tip to the head;
    /// its list names only those whose parents the VM lacks, so never the tip
    /// it expects, whose history the VM holds. The helper runs it before any
    /// git run (422 `bad_refs`).
    pub fn check_for(&self, q: &SeedQuery) -> Result<(), String> {
        q.check().map_err(|e| format!("comes with a bad query ({e})"))?;
        self.check()?;
        if q.branch != self.branch || q.detached != self.detached {
            return Err("names another head than its query (branch or detached)".into());
        }
        match q.mode {
            SeedMode::Clone | SeedMode::Replace if self.shallow.as_slice() != std::slice::from_ref(&self.head) => {
                Err(format!("does not list exactly its head as shallow, which a {} needs (its pack carries no history)", q.mode.name()))
            }
            SeedMode::Update if q.expect.as_ref().is_some_and(|tip| self.shallow.contains(tip)) => Err("lists the tip its update expects as shallow (the VM holds that tip's history)".into()),
            _ => Ok(()),
        }
    }
}

/// What the shim recorded when it seeded the VM (in memory: it survives a
/// suspend, not a new VM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedRecord {
    /// The workspace's VM path (one workspace per VM).
    pub path: String,
    /// How the last seed went in.
    pub mode: SeedMode,
    /// The branch it checked out; `None`: detached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The seeded commit (S).
    pub head: String,
    /// The seeded WIP commit, when the seed carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip: Option<String>,
    /// The tree the seed left in the worktree, when it was not the head's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_tree: Option<String>,
    /// The tree the seed left in the index, when it was not the head's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_tree: Option<String>,
    pub object_format: ObjectFormat,
    /// When (RFC 3339 UTC).
    pub at: String,
}

/// `GET /seed?path=`: the workspace as D3 decides on it. Never seeded:
/// every field `None` and both flags false.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedState {
    /// The last seed's record; `None` before the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<SeedRecord>,
    /// The checkout's HEAD commit now (T).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip: Option<String>,
    /// The branch checked out now; `None` when detached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Nothing to commit: the worktree and the index match the tip's tree
    /// and no untracked file (not ignored) exists. A VM seeded dirty is not
    /// clean, so D3 never fast-forwards it on its own.
    #[serde(default)]
    pub clean: bool,
    /// Unchanged since the seed: the tip is the seeded head and the worktree
    /// and index trees are the ones the seed left (what `replace` needs).
    #[serde(default)]
    pub pristine: bool,
}

/// What a `PUT /seed` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedApplied {
    Cloned,
    Updated,
    Replaced,
    /// The VM already held this head and WIP: nothing changed.
    UpToDate,
}

impl SeedApplied {
    /// The audit's and the census's word.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            SeedApplied::Cloned => "cloned",
            SeedApplied::Updated => "updated",
            SeedApplied::Replaced => "replaced",
            SeedApplied::UpToDate => "up_to_date",
        }
    }

    /// 201 for a change, 200 for none.
    #[must_use]
    pub fn status(self) -> u16 {
        if self == SeedApplied::UpToDate {
            200
        } else {
            201
        }
    }
}

/// The `PUT /seed` answer (201, or 200 when up to date).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedReply {
    pub outcome: SeedApplied,
    /// The commit checked out.
    pub head: String,
    /// The branch checked out; `None`: detached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The WIP and index commits applied uncommitted, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    /// The helper's time.
    pub ms: u64,
}

// ---- code-out ------------------------------------------------------------------------------

/// The `POST /codeout` body (§7): with `wip`, snapshot the uncommitted work
/// into a `refs/wip/*` ref first; then pack what the Mac lacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeoutRequest {
    pub path: String,
    /// Object ids the Mac holds, at most [`HAVES_MAX`]: the pack leaves out
    /// what they reach. The Mac names its HEAD and the seeded head first,
    /// then its box tips (the branches, then the newest `box/wip/*`) while
    /// they fit: the VM's branches are the agent's to multiply, and a have
    /// left out only makes the pack carry objects the Mac already holds,
    /// never a wrong one. The VM keeps only the ones it has.
    #[serde(default)]
    pub haves: Vec<String>,
    #[serde(default)]
    pub wip: bool,
    /// The largest pack the reply may carry (`[seed].max_fetch_mib`, `box
    /// fetch --max-mib`): larger is 413 `too_large` with the size.
    pub max_bytes: u64,
}

impl CodeoutRequest {
    /// The body's rules: a VM path, at most [`HAVES_MAX`] object ids, and
    /// `max_bytes` from 1 to [`SEED_BODY_MAX`].
    pub fn check(&self) -> Result<(), String> {
        vm_path_check(&self.path).map_err(|e| format!("the path {e}"))?;
        if self.haves.len() > HAVES_MAX {
            return Err(format!("names {} haves (at most {HAVES_MAX})", self.haves.len()));
        }
        if let Some(i) = self.haves.iter().position(|h| ObjectFormat::of_id(h).is_none()) {
            return Err(format!("has a have (number {i}) that is not an object id"));
        }
        if !(1..=SEED_BODY_MAX).contains(&self.max_bytes) {
            return Err(format!("asks for at most {} bytes (1 to {SEED_BODY_MAX})", self.max_bytes));
        }
        Ok(())
    }
}

/// The line before the pack in a `POST /codeout` reply: the VM's refs the
/// Mac fetches into `refs/remotes/box/*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeoutManifest {
    /// [`SeedManifest::V`]'s numbering.
    pub v: u8,
    pub object_format: ObjectFormat,
    /// The VM's refs by full name, to their commits: `refs/heads/*`,
    /// `refs/wip/*`, [`SEED_WIP_REF`], and `HEAD` when detached (no others).
    pub refs: BTreeMap<String, String>,
    /// The checkout's HEAD commit.
    pub head: String,
    /// The branch checked out; `None`: detached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The snapshot this request made (or the newest one, when nothing
    /// changed since it), one of `refs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_ref: Option<String>,
    /// Why no snapshot was made although asked (over `[seed].max_wip_mib`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_skipped: Option<String>,
}

impl CodeoutManifest {
    /// The manifest's rules: version [`SeedManifest::V`], the head an id of
    /// the object format, a branch git takes, every ref in its set and every
    /// id of the format, `HEAD` only when detached, a `wip_ref` among the
    /// refs and under [`WIP_REF_PREFIX`], never with `wip_skipped`. The Mac
    /// runs it before any byte of the pack is imported.
    pub fn check(&self) -> Result<(), String> {
        if self.v != SeedManifest::V {
            return Err(format!("is manifest v{} (this side reads v{})", self.v, SeedManifest::V));
        }
        let format = self.object_format;
        if !format.is_id(&self.head) {
            return Err(format!("has a head that is not a {} object id", format.name()));
        }
        if let Some(b) = &self.branch {
            branch_check(b).map_err(|e| format!("the branch {e}"))?;
        }
        for (name, id) in &self.refs {
            let allowed = if name == "HEAD" {
                self.branch.is_none()
            } else if let Some(b) = name.strip_prefix(HEADS_PREFIX) {
                branch_check(b).is_ok()
            } else {
                (name.starts_with(WIP_REF_PREFIX) && is_ref_name(name)) || name == SEED_WIP_REF
            };
            if !allowed {
                return Err(format!("names a ref outside refs/heads/*, refs/wip/*, {SEED_WIP_REF} and a detached HEAD"));
            }
            if !format.is_id(id) {
                return Err(format!("has a ref whose target is not a {} object id", format.name()));
            }
        }
        match (&self.wip_ref, &self.wip_skipped) {
            (Some(_), Some(_)) => Err("names a snapshot and why none was made".into()),
            (Some(w), None) if !w.starts_with(WIP_REF_PREFIX) || !self.refs.contains_key(w) => Err("names a snapshot that is not one of its refs/wip/* refs".into()),
            _ => Ok(()),
        }
    }
}

// ---- transcripts ---------------------------------------------------------------------------

/// `GET /transcript?rel=`: the VM's copy, as the agent's projects directory
/// holds it. S9's extended stat ([`StatQuery`]) adds the fields after
/// `mtime`, each left out when not asked for, so S8's documents read and
/// write as before; with `from` no whole-file sha256 is computed. The
/// default is an absent file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptStat {
    /// A regular file is there (a symlink is 409 `symlink_component`).
    pub present: bool,
    /// Its size; 0 when absent.
    #[serde(default)]
    pub size: u64,
    /// sha256 of its bytes (lowercase hex), when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Its mtime (RFC 3339 UTC), when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<String>,
    /// The file's inode, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
    /// With `from` at most `size`: sha256 of `[from, size)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_sha256: Option<String>,
    /// With `from`: sha256 of `[max(0, size - FP_SPAN), size)`, the fingerprint the Mac records when it commits `size`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_fp: Option<String>,
    /// With `fp`: whether the VM's `[max(0, from - FP_SPAN), from)` hashes to it (false when `from` is past `size`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp_ok: Option<bool>,
    /// With `subtree`: the subtree's regular files, by rel (symlinks skipped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subtree: Vec<SubtreeFile>,
}

// ---- S9: the transcript store's transfers (G5 serves them, G4 asks) ------------------------

/// `GET /transcript?rel=&from=&fp=&subtree=` (S9): the stat a sync and a restore ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatQuery {
    /// [`transcript_rel_check`]'s rel.
    pub rel: String,
    /// The length S3 holds: `delta_sha256` covers `[from, size)`, `end_fp` the `FP_SPAN` bytes before `size`;
    /// no whole-file sha256 is computed. `None`: S8's stat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    /// The manifest's fingerprint at `from` (lowercase hex sha256 of `[max(0, from - FP_SPAN), from)`): `fp_ok`.
    /// Only with `from`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// Also list the `<slug>/<uuid>/` subtree's regular files (the rel must be `<slug>/<uuid>.jsonl`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub subtree: bool,
}

impl StatQuery {
    /// The query's rules: the rel; `fp` only with `from`, 64 lowercase hex;
    /// `subtree` only for a `<slug>/<uuid>.jsonl` rel.
    pub fn check(&self) -> Result<(), String> {
        transcript_rel_check(&self.rel).map_err(|e| format!("the transcript's rel {e}"))?;
        match (&self.from, &self.fp) {
            (None, Some(_)) => return Err("names a fingerprint without from".into()),
            (_, Some(fp)) if !is_sha256_hex(fp) => return Err("names a fingerprint that is not 64 lowercase hex digits".into()),
            _ => {}
        }
        if self.subtree && !is_main_rel(&self.rel) {
            return Err("asks for a subtree of a rel that is not <slug>/<uuid>.jsonl".into());
        }
        Ok(())
    }

    /// The query's pairs: the rel, then `from`, `fp` and `subtree` (`true`) when set, in that order.
    #[must_use]
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("rel", self.rel.clone())];
        if let Some(from) = self.from {
            out.push(("from", from.to_string()));
        }
        if let Some(fp) = &self.fp {
            out.push(("fp", fp.clone()));
        }
        if self.subtree {
            out.push(("subtree", "true".to_string()));
        }
        out
    }
}

/// One regular file of a session's subtree (`TranscriptStat::subtree`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtreeFile {
    /// Its rel (`<slug>/<uuid>/<sub…>`, [`transcript_rel_check`]'s).
    pub rel: String,
    pub size: u64,
    /// sha256 of its bytes, lowercase hex: its key is `v1/<sid>/vm/f/<sha256>`.
    pub sha256: String,
}

/// `POST /transcript/push`: `len` bytes of the VM's copy from `from`, piped helper to curl to S3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptPush {
    pub rel: String,
    pub from: u64,
    /// 1 to `wire::s3::PUSH_MAX`.
    pub len: u64,
    /// sha256 of those bytes (lowercase hex), the stat's `delta_sha256`: the signed checksum's.
    pub sha256: String,
    /// A PUT signed for exactly `len`, `x-amz-checksum-sha256` of `sha256`, `If-None-Match: *` and `owner`
    /// (`X-Amz-SignedHeaders` exactly `SIGNED_HEADERS_PUT`).
    pub url: PresignedUrl,
    /// `x-amz-expected-bucket-owner`: 12 digits.
    pub owner: String,
    /// squid, `http://<RFC 1918 IPv4>:<port>` (`wire::s3::proxy_check`); `None` in the lab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

impl TranscriptPush {
    /// The body's rules: the rel (the main transcript, or one file of its
    /// subtree), `len` 1 to `PUSH_MAX`, a sha256, the owner, the proxy, and
    /// the URL a PUT of exactly these bytes: `SIGNED_HEADERS_PUT`, no query
    /// but the signature's, and a key that fits them: a `Segment` at `from`
    /// or a `Base` from 0 of the rel's session for the main transcript, the
    /// `File` of this sha256 from 0 for a subtree file.
    pub fn check(&self) -> Result<(), String> {
        let session = transfer_rel(&self.rel)?;
        if !(1..=PUSH_MAX).contains(&self.len) {
            return Err(format!("pushes {} bytes (1 to {PUSH_MAX})", self.len));
        }
        if !is_sha256_hex(&self.sha256) {
            return Err("names a sha256 that is not 64 lowercase hex digits".into());
        }
        owner_and_proxy(&self.owner, self.proxy.as_deref())?;
        let key = transfer_url(&self.url, SIGNED_HEADERS_PUT, false, "push")?;
        let fits = match &key {
            S3Key::Segment { offset, .. } => is_main_rel(&self.rel) && *offset == self.from,
            S3Key::Base { .. } => is_main_rel(&self.rel) && self.from == 0,
            S3Key::File { sha256, .. } => !is_main_rel(&self.rel) && *sha256 == self.sha256 && self.from == 0,
            _ => false,
        };
        if !fits || key.session() != Some(session) {
            return Err("pushes to a key that does not fit its bytes (a segment at from, a base from 0, a subtree file by its sha256, of the rel's session)".into());
        }
        Ok(())
    }
}

/// The `POST /transcript/push` answer (200 whenever curl reported an HTTP status, whatever `s3_status` is).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptPushReply {
    /// S3's HTTP status: 200 stored, 412 the key holds an object already, 400 `BadDigest`, 403 …
    pub s3_status: u16,
    /// S3's `<Code>` on an error (at most 64 characters of `[A-Za-z0-9]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3_code: Option<String>,
    /// `x-amz-version-id` of a 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// What the shim streamed, and its sha256.
    pub len: u64,
    pub sha256: String,
}

/// `POST /transcript/pull`: the VM's copy rebuilt from `parts` in order, each checked, then renamed into place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptPull {
    pub rel: String,
    /// 1 to `wire::s3::PULL_PARTS_MAX`.
    pub parts: Vec<PullPart>,
    /// sha256 of the whole file, when the Mac knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

impl TranscriptPull {
    /// The body's rules: the rel (either kind); 1 to `PULL_PARTS_MAX` parts
    /// of at most `PULL_MAX` bytes in all, each URL a GET
    /// (`SIGNED_HEADERS_GET`, no query but the signature's and a
    /// `versionId`) of a `Mac`, `Base`, `Segment`, `Tail` or `File` key of
    /// the rel's session (a `Tail` only in a pull of the main transcript:
    /// a tail is never another file's, [`TranscriptTail`]), each part's
    /// sha256 64 lowercase hex (only a tail's may be unknown); the whole
    /// file's sha256, the owner, the proxy.
    pub fn check(&self) -> Result<(), String> {
        let session = transfer_rel(&self.rel)?;
        if self.parts.is_empty() || self.parts.len() > PULL_PARTS_MAX {
            return Err(format!("pulls {} parts (1 to {PULL_PARTS_MAX})", self.parts.len()));
        }
        let total = self.parts.iter().try_fold(0u64, |sum, p| sum.checked_add(p.len));
        if total.is_none_or(|t| t > PULL_MAX) {
            return Err(format!("pulls more than {PULL_MAX} bytes in all"));
        }
        if self.sha256.as_deref().is_some_and(|s| !is_sha256_hex(s)) {
            return Err("names a sha256 that is not 64 lowercase hex digits".into());
        }
        owner_and_proxy(&self.owner, self.proxy.as_deref())?;
        for (i, part) in self.parts.iter().enumerate() {
            let key = transfer_url(&part.url, SIGNED_HEADERS_GET, true, "pull part")?;
            if matches!(key, S3Key::EgressCheck { .. } | S3Key::OutsideProbe { .. }) || key.session() != Some(session) {
                return Err(format!("pulls a part (number {i}) of a key that is not of the rel's session"));
            }
            if matches!(key, S3Key::Tail { .. }) && !is_main_rel(&self.rel) {
                return Err(format!("pulls a tail (part number {i}) into a rel that is not <slug>/<uuid>.jsonl: a tail is only ever the session's main transcript"));
            }
            match (&part.sha256, &key) {
                (Some(s), _) if !is_sha256_hex(s) => return Err(format!("names a part (number {i}) whose sha256 is not 64 lowercase hex digits")),
                (None, S3Key::Tail { .. }) | (Some(_), _) => {}
                (None, _) => return Err(format!("names a part (number {i}) without its sha256 that is no tail")),
            }
        }
        Ok(())
    }
}

/// One part of a pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullPart {
    /// A GET (`X-Amz-SignedHeaders` exactly `SIGNED_HEADERS_GET`) by `versionId` when the Mac knows it; a `Tail` part
    /// (found by listing) and a `File` part whose version a 412 left unknown read the current version.
    pub url: PresignedUrl,
    pub len: u64,
    /// `None` only for a tail object, which the Mac never saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The `POST /transcript/pull` answer: 201 written, 200 not (a part's status, length or sha256 did not match).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptPullReply {
    pub written: bool,
    /// The VM's copy's size now (the old one's when nothing was written).
    pub size: u64,
    /// sha256 of the file written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// One per part tried, in order; the first bad part ends the pull.
    pub parts: Vec<PullPartReport>,
}

/// What one part of a pull brought.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullPartReport {
    pub s3_status: u16,
    pub len: u64,
    pub sha256: String,
    pub ok: bool,
}

/// `GET /transcript/view?rel=&n=`: `n` 1 to `wire::view::VIEW_MESSAGES_MAX`, the rel a `<slug>/<uuid>.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewQuery {
    pub rel: String,
    pub n: u32,
}

impl ViewQuery {
    /// The query's rules: a `<slug>/<uuid>.jsonl` rel, `n` from 1 to `VIEW_MESSAGES_MAX`.
    pub fn check(&self) -> Result<(), String> {
        transcript_rel_check(&self.rel).map_err(|e| format!("the transcript's rel {e}"))?;
        if !is_main_rel(&self.rel) {
            return Err("asks for the view of a rel that is not <slug>/<uuid>.jsonl".into());
        }
        if !(1..=crate::wire::view::VIEW_MESSAGES_MAX).contains(&self.n) {
            return Err(format!("asks for {} messages (1 to {})", self.n, crate::wire::view::VIEW_MESSAGES_MAX));
        }
        Ok(())
    }

    /// The query's pairs: the rel, then `n`.
    #[must_use]
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        vec![("rel", self.rel.clone()), ("n", self.n.to_string())]
    }
}

/// `POST /transcript/tail` (S9 §1.4): held by the shim for `/suspend` and
/// `/terminate`. Only ever the session's main transcript (`<slug>/<uuid>.jsonl`):
/// its key names no file, so another file's tail would read back as the main
/// transcript's at a restore. A subtree file reaches S3 whole at the next
/// sync (`v1/<sid>/vm/f/<sha256>`); one changed after the last sync and
/// before `/suspend` or `/terminate` is lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptTail {
    /// The session's main transcript: `<slug>/<uuid>.jsonl`.
    pub rel: String,
    /// The committed length: the tail is `[from, size)` at the hook.
    pub from: u64,
    /// A PUT of `v1/<sid>/vm/g<gen>/t/<from:016x>` (`X-Amz-SignedHeaders` exactly `SIGNED_HEADERS_TAIL`), `TAIL_EXPIRY`.
    pub url: PresignedUrl,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Unix seconds: dropped then.
    pub expires_at: u64,
}

impl TranscriptTail {
    /// The body's rules: the rel (the session's main transcript only), the
    /// owner, the proxy, and a URL that PUTs (`SIGNED_HEADERS_TAIL`, no
    /// query but the signature's) the `Tail` at `from` of the rel's session.
    pub fn check(&self) -> Result<(), String> {
        let session = transfer_rel(&self.rel)?;
        if !is_main_rel(&self.rel) {
            return Err("names a rel that is not <slug>/<uuid>.jsonl: a tail is only ever the session's main transcript (its key names no file)".into());
        }
        owner_and_proxy(&self.owner, self.proxy.as_deref())?;
        let key = transfer_url(&self.url, SIGNED_HEADERS_TAIL, false, "tail")?;
        if !matches!(&key, S3Key::Tail { offset, .. } if *offset == self.from) || key.session() != Some(session) {
            return Err("puts its tail to a key that is not the tail at from of the rel's session".into());
        }
        Ok(())
    }
}

/// The `transcript-read` op's head reply: the file's size and inode; `len` bytes follow the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptReadReply {
    pub size: u64,
    pub ino: u64,
}

/// The `transcript-write` op's head reply, written after the `commit` line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptWriteReply {
    pub size: u64,
    pub sha256: String,
}

/// The `git-cgi` op's head reply, before the CGI's raw output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCgiReply {
    pub object_format: ObjectFormat,
    pub git_version: String,
}

/// The head `reply` of an op whose own reply can pass [`HEAD_LINE_MAX`] (`transcript-view`; `transcript-stat --subtree`):
/// that reply follows the head as exactly `len` bytes (at most [`JSON_PAYLOAD_MAX`]) of its compact JSON, whose sha256
/// (lowercase hex) this is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonPayloadReply {
    pub sha256: String,
}

/// 64 lowercase hex digits (a sha256).
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Is `rel` (one [`transcript_rel_check`] passed) a session's main transcript, `<slug>/<uuid>.jsonl`?
fn is_main_rel(rel: &str) -> bool {
    rel.split('/').count() == 2
}

/// A transfer's rel ([`transcript_rel_check`]'s, either kind) and the session it is of.
fn transfer_rel(rel: &str) -> Result<&str, String> {
    transcript_rel_check(rel).map_err(|e| format!("the transcript's rel {e}"))?;
    let second = rel.split('/').nth(1).unwrap_or_default();
    Ok(second.strip_suffix(".jsonl").unwrap_or(second))
}

/// The bucket owner (12 digits) and the proxy (`wire::s3::proxy_check`) a transfer names.
fn owner_and_proxy(owner: &str, proxy: Option<&str>) -> Result<(), String> {
    if !is_account_id(owner) {
        return Err("names a bucket owner that is not 12 digits".into());
    }
    if let Some(p) = proxy {
        proxy_check(p).map_err(|e| format!("the proxy {e}"))?;
    }
    Ok(())
}

/// The key a transfer's URL names, once the URL is narrowed for the VM: an
/// object's key, `signed` exactly its signed headers, and no query
/// parameter but the signature's (and a `versionId` when `version` allows one).
fn transfer_url(url: &PresignedUrl, signed: &str, version: bool, what: &str) -> Result<S3Key, String> {
    if url.signed_headers() != signed {
        return Err(format!("has a {what} URL signed over other headers than {signed}"));
    }
    if let Some(extra) = url.param_names().into_iter().find(|n| !n.starts_with("X-Amz-") && !(version && *n == "versionId")) {
        return Err(format!("has a {what} URL carrying {extra}, which a {what} never signs"));
    }
    S3Key::parse(url.key()).ok_or_else(|| format!("has a {what} URL that names no object of the store"))
}

// ---- settings (T8.7) ---------------------------------------------------------------------

/// Where a settings file of the VM's claude lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsScope {
    /// The agent's `~/.claude/settings.json`.
    User,
    /// The workspace's `.claude/settings.json`.
    Project,
    /// The workspace's `.claude/settings.local.json` (where "don't ask
    /// again" rules land).
    Local,
}

impl SettingsScope {
    /// Every scope, in a capture's order.
    pub const ALL: [SettingsScope; 3] = [SettingsScope::User, SettingsScope::Project, SettingsScope::Local];

    /// As the wire spells it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SettingsScope::User => "user",
            SettingsScope::Project => "project",
            SettingsScope::Local => "local",
        }
    }
}

/// The keys of `projects[<path>]` in the agent's `.claude.json` a capture
/// carries (every other key there stays in the VM).
pub const PROJECT_KEYS: [&str; 5] = ["allowedTools", "enabledMcpjsonServers", "disabledMcpjsonServers", "enableAllProjectMcpServers", "hasTrustDialogAccepted"];

/// One settings file, as the agent's helper read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsFile {
    pub scope: SettingsScope,
    /// Where it is in the VM.
    pub path: String,
    /// Something is at the path (a regular file, or what `skipped` names).
    pub present: bool,
    /// Its size in bytes; 0 when absent.
    #[serde(default)]
    pub size: u64,
    /// sha256 of its bytes (lowercase hex), for a regular file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Its text, for a regular file of UTF-8 of at most [`SETTINGS_FILE_MAX`] bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Why a present file's text is not here (a symlink, not a regular file,
    /// larger than the cap, not UTF-8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// `GET /settings?path=`: what the VM's claude holds for the workspace,
/// captured into the session's quarantine (`settings_capture`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsCapture {
    /// The workspace's VM path.
    pub path: String,
    /// The files, one per scope, in [`SettingsScope::ALL`]'s order.
    pub files: Vec<SettingsFile>,
    /// The [`PROJECT_KEYS`] of `projects[path]` in the agent's
    /// `.claude.json`, as found; an absent key is left out.
    #[serde(default)]
    pub project: BTreeMap<String, serde_json::Value>,
    /// When the helper read them (RFC 3339 UTC).
    pub at: String,
}

impl SettingsCapture {
    /// The capture's rules: a VM path, at most one file per scope in their
    /// order, every text at most [`SETTINGS_FILE_MAX`] bytes and as long as
    /// its size, only [`PROJECT_KEYS`].
    pub fn check(&self) -> Result<(), String> {
        vm_path_check(&self.path).map_err(|e| format!("the path {e}"))?;
        if !self.files.windows(2).all(|w| w[0].scope < w[1].scope) {
            return Err("has its files out of scope order, or two of one scope".into());
        }
        for f in &self.files {
            if let Some(text) = &f.text {
                if text.len() > SETTINGS_FILE_MAX || text.len() as u64 != f.size {
                    return Err(format!("has a {} text of {} bytes for a file of {} (at most {SETTINGS_FILE_MAX})", f.scope.name(), text.len(), f.size));
                }
            }
        }
        if let Some(k) = self.project.keys().find(|k| !PROJECT_KEYS.contains(&k.as_str())) {
            return Err(format!("carries the project key {k:?}, which is not allowlisted"));
        }
        Ok(())
    }
}

// ---- the helper's head line and the state view ---------------------------------------------

/// The first line the agent's helper (`ai-env shim-io <op>`) prints: `{"ok":
/// true,"reply":…}` with the op's reply (and `len`, the payload's bytes
/// after the line: a code-out's pack), or a refusal's fields with
/// `"ok":false` (a [`WsRefusal`] once `ok` is dropped). A non-zero exit, or a
/// head that is neither, is an internal failure the route answers with 500.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperHead<T> {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SeedState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The op's reply ([`SeedState`], [`SeedReply`], [`CodeoutManifest`],
    /// [`SnapshotReply`], [`TranscriptStat`], [`SettingsCapture`]; S9's [`TranscriptReadReply`],
    /// [`TranscriptWriteReply`], [`GitCgiReply`], [`JsonPayloadReply`]).
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    pub reply: Option<T>,
    /// The bytes of payload after the line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
}

impl<T> HelperHead<T> {
    /// An op's reply.
    #[must_use]
    pub fn ok(reply: T, len: Option<u64>) -> HelperHead<T> {
        HelperHead { ok: true, code: None, message: None, state: None, size: None, reply: Some(reply), len }
    }

    /// An op's refusal.
    #[must_use]
    pub fn refused(r: WsRefusal) -> HelperHead<T> {
        HelperHead { ok: false, code: Some(r.code), message: Some(r.message), state: r.state, size: r.size, reply: None, len: None }
    }

    /// `Some(Ok((reply, len)))`, `Some(Err(refusal))`, or `None` for a head
    /// that is neither (ok without a reply, a refusal without a code). The
    /// helper runs as the agent, so its words are the agent's to shape: a
    /// refusal's code is one of [`refusal::ALL`] (any other is `git_failed`),
    /// its message made one scrubbed line by [`WsRefusal::new`], its state and
    /// size kept.
    #[must_use]
    pub fn outcome(self) -> Option<Result<(T, Option<u64>), WsRefusal>> {
        match (self.ok, self.reply, self.code) {
            (true, Some(reply), _) => Some(Ok((reply, self.len))),
            (false, _, Some(code)) => {
                let r = WsRefusal::new(known_refusal(&code).unwrap_or(refusal::GIT_FAILED), &self.message.unwrap_or_default());
                Some(Err(WsRefusal { state: self.state, size: self.size, ..r }))
            }
            _ => None,
        }
    }
}

/// The `snapshot` op's reply (the `/suspend` hook; the shim logs it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReply {
    /// The `refs/wip/*` made or kept; `None` when the checkout matched its head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_ref: Option<String>,
    /// Why none was made although the checkout changed (over the cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_skipped: Option<String>,
    pub ms: u64,
}

/// `/health/detail`'s workspace (`frame::HealthDetail::workspace`): what
/// the shim holds about its one workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceView {
    /// The last seed's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<SeedRecord>,
    /// The op holding the workspace now (`seed-apply`, `codeout`, `snapshot`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busy: Option<String>,
    /// Helpers running now (each holds off the idle sweep).
    #[serde(default)]
    pub helpers: u32,
    /// The newest `refs/wip/*` a snapshot made, and when (RFC 3339 UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_wip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_wip_at: Option<String>,
}

// ---- framing -------------------------------------------------------------------------------

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `head` as its line: compact JSON (which never holds a raw newline) and
/// `\n`, at most [`HEAD_LINE_MAX`] bytes in all.
pub fn head_line<T: Serialize>(head: &T) -> io::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(head).map_err(|e| invalid(format!("the head line does not serialise: {e}")))?;
    line.push(b'\n');
    if line.len() > HEAD_LINE_MAX {
        return Err(invalid(format!("the head line is {} bytes (at most {HEAD_LINE_MAX})", line.len())));
    }
    Ok(line)
}

/// Write `head`'s line, then all of `payload`: a `PUT /seed` body (the
/// [`SeedManifest`], then the pack), a `POST /codeout` reply (the
/// [`CodeoutManifest`], then the pack), a helper's stdout (its
/// [`HelperHead`], then the payload). The bytes written in all.
pub fn write_framed<W: Write + ?Sized, R: Read + ?Sized, T: Serialize>(out: &mut W, head: &T, payload: &mut R) -> io::Result<u64> {
    let line = head_line(head)?;
    out.write_all(&line)?;
    let copied = io::copy(payload, out)?;
    Ok(line.len() as u64 + copied)
}

/// The head line of a framed body, without its `\n`: at most `cap` bytes
/// are read (the `\n` included), and nothing past the `\n`, so `input` is
/// left at the payload's first byte. A line longer than `cap`, or a body
/// that ends before its `\n`, is `InvalidData` or `UnexpectedEof`.
pub fn read_head_line<R: BufRead + ?Sized>(input: &mut R, cap: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let read = input.take(cap as u64).read_until(b'\n', &mut line)?;
    end_head_line(line, read, cap)
}

/// [`read_head_line`] on an async reader (the helper's stdout in the shim,
/// a reply body on the Mac).
pub async fn read_head_line_async<R: AsyncBufRead + Unpin + ?Sized>(input: &mut R, cap: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let read = input.take(cap as u64).read_until(b'\n', &mut line).await?;
    end_head_line(line, read, cap)
}

/// The line read, its `\n` taken off, or why there was none.
fn end_head_line(mut line: Vec<u8>, read: usize, cap: usize) -> io::Result<Vec<u8>> {
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(line);
    }
    if read >= cap {
        return Err(invalid(format!("the head line is longer than {cap} bytes")));
    }
    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the body ended before its head line did"))
}

/// A head line (without its `\n`) as `T`.
pub fn parse_head<T: DeserializeOwned>(line: &[u8]) -> Result<T, String> {
    serde_json::from_slice(line).map_err(|e| format!("the head line does not parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;
    use std::collections::BTreeSet;

    const SLUG: &str = "-Users-mike-Documents-DeFi-ai-env";
    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    /// Й as И + U+0306 (NFD), and the precomposed Й (NFC), as `wire::slug`'s test spells them.
    const NFD: &str = "/Users/mike/\u{0418}\u{0306}\u{043e}\u{0433}\u{0430}";
    const NFC: &str = "/Users/mike/\u{0419}\u{043e}\u{0433}\u{0430}";
    const H: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
    const W: &str = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1";

    #[test]
    fn vm_paths_are_absolute_nfc_and_free_of_dot_components() {
        for good in ["/Users/mike/Documents/DeFi/ai-env", NFC, "/", "/a b/c.d/-x"] {
            assert_eq!(vm_path_check(good), Ok(()), "{good:?}");
        }
        let exactly = format!("/{}", "a".repeat(VM_PATH_MAX - 1));
        assert_eq!(vm_path_check(&exactly), Ok(()), "exactly {VM_PATH_MAX} bytes");
        let too_long = format!("/{}", "a".repeat(VM_PATH_MAX));
        let cases: [(&str, &str); 10] = [
            (NFD, "not in Unicode NFC"),
            ("", "is empty"),
            ("Users/mike/x", "is not absolute"),
            ("/Users/mike/../root", "`..`"),
            ("/Users/mike/./x", "`.`"),
            ("/Users//mike", "empty component"),
            ("/Users/mike/", "empty component"),
            ("/Users/mi\0ke", "NUL"),
            ("/Users/mike/x/..", "`..`"),
            (&too_long, "4097 bytes long"),
        ];
        for (bad, why) in cases {
            let e = vm_path_check(bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
            assert!(!e.contains("mike"), "the rule, never the path: {e}");
        }
    }

    /// The NFD Cyrillic form is refused as it is and accepted once
    /// normalised: the Mac sends `vm_path_of`'s form, the VM checks it.
    #[test]
    fn nfc_normalises_and_vm_path_of_gives_the_vm_form() {
        use std::os::unix::ffi::OsStrExt as _;
        assert_ne!(NFD, NFC);
        assert_eq!(nfc(NFD), NFC);
        assert_eq!(nfc(NFC), NFC, "idempotent");
        assert!(vm_path_check(NFD).is_err() && vm_path_check(&nfc(NFD)).is_ok());
        assert_eq!(vm_path_of(Path::new(NFD)).as_deref(), Ok(NFC));
        assert_eq!(vm_path_of(Path::new("/Users/mike/x")).as_deref(), Ok("/Users/mike/x"));
        let latin1 = Path::new(std::ffi::OsStr::from_bytes(b"/Users/mike/caf\xe9"));
        assert_eq!(vm_path_of(latin1), Err("is not UTF-8".to_string()));
        assert!(vm_path_of(Path::new("relative")).unwrap_err().contains("not absolute"));
        assert!(vm_path_of(Path::new("/a/../b")).is_err(), "a traversal is refused after normalising too");
    }

    #[test]
    fn transcript_rels_are_the_mirrors_own_paths() {
        let deepest = format!("{SLUG}/{ID}/{}/f.jsonl", (1..=TRANSCRIPT_DIRS_MAX).map(|n| format!("d{n}")).collect::<Vec<_>>().join("/"));
        for good in [
            format!("{SLUG}/{ID}.jsonl"),
            format!("{SLUG}/{ID}/subagents/agent-a34bd0532e489ebd0.jsonl"),
            format!("{SLUG}/{ID}/subagents/agent-a1.meta.json"),
            format!("{SLUG}/{ID}/subagents/workflows/x.jsonl"),
            format!("{SLUG}/{}/subagents/a.jsonl", ID.to_uppercase()),
            format!("{}/{ID}.jsonl", "a".repeat(SLUG_MAX)),
            // A `CLAUDE_CODE_PROJECT_DIR_NAME` the CLI honours (`wire::slug::override_dir_name`).
            format!("my_proj/{ID}.jsonl"),
            format!("a_b/{ID}/subagents/agent-a1.jsonl"),
            deepest.clone(),
        ] {
            assert_eq!(transcript_rel_check(&good), Ok(()), "{good}");
        }
        let too_deep = deepest.replace("/f.jsonl", "/d9/f.jsonl");
        for bad in [
            String::new(),
            SLUG.to_string(),
            format!("{SLUG}/{ID}.json"),
            format!("{SLUG}/{ID}"),
            format!("{SLUG}/{ID}/x.jsonl"),
            format!("{SLUG}/not-a-uuid.jsonl"),
            format!("{SLUG}/../{ID}.jsonl"),
            format!("../{SLUG}/{ID}.jsonl"),
            format!("/{SLUG}/{ID}.jsonl"),
            format!("{SLUG}//{ID}.jsonl"),
            format!("{SLUG}/{ID}/../x/y.jsonl"),
            format!("{SLUG}/{ID}/sub/../../{ID}.jsonl"),
            format!("{SLUG}/{ID}/sub/.hidden.jsonl"),
            format!("{SLUG}/{ID}/sub/x.txt"),
            format!("{SLUG}/{ID}/sub/x y.jsonl"),
            format!("{SLUG}/{ID}/sub/"),
            format!("a.b/{ID}.jsonl"),
            format!("a b/{ID}.jsonl"),
            format!("{}/{ID}.jsonl", "a".repeat(SLUG_MAX + 1)),
            format!("{SLUG}/{ID}/sub/{}.jsonl", "x".repeat(SEGMENT_MAX)),
            too_deep,
        ] {
            assert!(transcript_rel_check(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn uuids_object_ids_branches_and_refs() {
        assert!(is_uuid(ID) && is_uuid(&ID.to_uppercase()));
        for bad in ["", "not-a-uuid", &ID[..35], &format!("{ID}x"), "0199a1b2xc3d4-7e5f-8a9b-0c1d2e3f4a5b", "../../etc/passwd-0000-0000-000000000"] {
            assert!(!is_uuid(bad), "{bad:?}");
        }
        assert_eq!(ObjectFormat::of_id(H), Some(ObjectFormat::Sha1));
        assert_eq!(ObjectFormat::of_id(&H.repeat(2)[..64]), Some(ObjectFormat::Sha256));
        for bad in ["", &H[..39], &H.to_uppercase(), &format!("{}g", &H[..39]), "HEAD", "refs/heads/dev"] {
            assert_eq!(ObjectFormat::of_id(bad), None, "{bad:?}");
        }
        assert!(ObjectFormat::Sha1.is_id(H) && !ObjectFormat::Sha256.is_id(H));
        assert_eq!((ObjectFormat::Sha1.hex_len(), ObjectFormat::Sha256.hex_len()), (40, 64));
        for good in ["dev", "feature/x-1", "rel.2", "\u{0439}\u{043e}\u{0433}\u{0430}"] {
            assert_eq!(branch_check(good), Ok(()), "{good:?}");
        }
        for bad in ["", "HEAD", "-x", "a..b", "a b", "a~1", "a^", "a:b", "a?", "a*", "a[", "a\\b", "a/", "/a", "a//b", ".a", "a/.b", "a.lock", "a.", "@", "a@{1}", "a\u{7f}", "a\tb"] {
            assert!(branch_check(bad).is_err(), "{bad:?}");
        }
        for good in ["HEAD", "refs/heads/dev", "refs/wip/20261012T101530Z-1", SEED_REF, SEED_WIP_REF] {
            assert!(is_ref_name(good), "{good}");
        }
        assert!(!is_ref_name(&format!("refs/heads/{}", "x".repeat(REF_NAME_MAX))));
    }

    fn query(mode: SeedMode, branch: Option<&str>, detached: bool, expect: Option<&str>) -> SeedQuery {
        SeedQuery { path: NFC.into(), mode, branch: branch.map(str::to_string), detached, expect: expect.map(str::to_string) }
    }

    #[test]
    fn seed_queries_name_one_head_and_expect_per_mode() {
        assert_eq!(query(SeedMode::Clone, Some("dev"), false, None).check(), Ok(()));
        assert_eq!(query(SeedMode::Update, None, true, Some(H)).check(), Ok(()));
        assert_eq!(query(SeedMode::Replace, Some("dev"), false, Some(H)).check(), Ok(()));
        for (q, why) in [
            (query(SeedMode::Clone, Some("dev"), false, Some(H)), "expects no tip"),
            (query(SeedMode::Update, Some("dev"), false, None), "update needs expect"),
            (query(SeedMode::Replace, None, true, None), "replace needs expect"),
            (query(SeedMode::Update, Some("dev"), false, Some("dev")), "not an object id"),
            (query(SeedMode::Clone, Some("dev"), true, None), "both"),
            (query(SeedMode::Clone, None, false, None), "neither"),
            (query(SeedMode::Clone, Some("a..b"), false, None), "the branch is not"),
            (SeedQuery { path: NFD.into(), ..query(SeedMode::Clone, Some("dev"), false, None) }, "the path is not in Unicode NFC"),
        ] {
            let e = q.check().unwrap_err();
            assert!(e.contains(why), "{q:?}: {e}");
        }
        let q = query(SeedMode::Update, None, true, Some(H));
        assert_eq!(q.pairs(), vec![("path", NFC.to_string()), ("mode", "update".to_string()), ("detached", "true".to_string()), ("expect", H.to_string())]);
        assert_eq!(query(SeedMode::Clone, Some("dev"), false, None).pairs(), vec![("path", NFC.to_string()), ("mode", "clone".to_string()), ("branch", "dev".to_string())]);
        assert_eq!(PathQuery { path: NFC.into() }.pairs(), vec![("path", NFC.to_string())]);
        assert_eq!(RelQuery { rel: "r".into() }.pairs(), vec![("rel", "r".to_string())]);
        assert_eq!((SeedMode::Clone.budget(), SeedMode::Update.budget(), SeedMode::Replace.budget()), (budget::SEED_CLONE, budget::SEED_UPDATE, budget::SEED_UPDATE));
    }

    fn manifest() -> SeedManifest {
        let mut m = SeedManifest { v: 1, object_format: ObjectFormat::Sha1, branch: Some("dev".into()), detached: false, head: H.into(), wip: Some(W.into()), index: None, shallow: vec![H.into()], refs: BTreeMap::new() };
        m.refs = m.expected_refs();
        m
    }

    #[test]
    fn seed_manifests_carry_exactly_their_refs() {
        let m = manifest();
        assert_eq!(m.check(), Ok(()));
        let names: Vec<&str> = m.refs.keys().map(String::as_str).collect();
        assert_eq!(names, ["refs/ai-env/seed", "refs/ai-env/seed-wip", "refs/heads/dev"]);
        let detached = SeedManifest { branch: None, detached: true, wip: None, refs: BTreeMap::from([(SEED_REF.to_string(), H.to_string())]), ..manifest() };
        assert_eq!(detached.check(), Ok(()));
        let mut extra = manifest();
        extra.refs.insert("refs/tags/v1".into(), H.into());
        let mut moved = manifest();
        moved.refs.insert(SEED_REF.into(), W.into());
        for (bad, why) in [
            (SeedManifest { v: 2, ..manifest() }, "v2"),
            (SeedManifest { object_format: ObjectFormat::Sha256, ..manifest() }, "not a sha256 object id"),
            (SeedManifest { index: Some(H.into()), wip: None, refs: detached.refs.clone(), branch: None, detached: true, ..manifest() }, "no wip"),
            (SeedManifest { shallow: vec![H.into(); HAVES_MAX + 1], ..manifest() }, "shallow commits"),
            (SeedManifest { shallow: vec!["HEAD".into()], ..manifest() }, "shallow commit that is not"),
            (extra, "refs other than"),
            (moved, "refs other than"),
            (SeedManifest { detached: true, ..manifest() }, "both"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }

    /// D7: a manifest matches the query it came with: its head, and the
    /// shallow boundary of its mode (a clone or a replace marks exactly its
    /// head; an update only the commits whose parents the VM lacks, never the
    /// tip it expects). An empty or foreign boundary would leave a
    /// history-less clone git takes for a complete one.
    #[test]
    fn a_seed_manifest_matches_its_query_and_its_modes_shallow_boundary() {
        const T: &str = "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2";
        const B: &str = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3";
        let clone = query(SeedMode::Clone, Some("dev"), false, None);
        let replace = query(SeedMode::Replace, Some("dev"), false, Some(T));
        let update = query(SeedMode::Update, Some("dev"), false, Some(T));
        let with = |shallow: &[&str]| SeedManifest { shallow: shallow.iter().map(|s| (*s).to_string()).collect(), ..manifest() };
        for (m, q) in [(with(&[H]), &clone), (with(&[H]), &replace), (with(&[]), &update), (with(&[B]), &update), (with(&[H]), &update)] {
            assert_eq!(m.check_for(q), Ok(()), "{m:?} for {q:?}");
        }
        let detached = SeedManifest { branch: None, detached: true, wip: None, refs: BTreeMap::from([(SEED_REF.to_string(), H.to_string())]), ..manifest() };
        assert_eq!(detached.check_for(&query(SeedMode::Clone, None, true, None)), Ok(()));
        for (m, q, why) in [
            (with(&[]), &clone, "exactly its head as shallow, which a clone needs"),
            (with(&[W]), &clone, "exactly its head"),
            (with(&[B]), &clone, "exactly its head"),
            (with(&[H, B]), &clone, "exactly its head"),
            (with(&[]), &replace, "which a replace needs"),
            (with(&[B, T]), &update, "the tip its update expects"),
            (manifest(), &query(SeedMode::Clone, Some("main"), false, None), "another head"),
            (manifest(), &query(SeedMode::Clone, None, true, None), "another head"),
            (detached.clone(), &clone, "another head"),
            (manifest(), &query(SeedMode::Clone, Some("dev"), false, Some(T)), "comes with a bad query (a clone expects no tip"),
            (SeedManifest { v: 2, ..manifest() }, &clone, "v2"),
        ] {
            let e = m.check_for(q).unwrap_err();
            assert!(e.contains(why), "{m:?} for {q:?}: {e}");
        }
    }

    #[test]
    fn codeout_requests_and_manifests_name_their_bounds() {
        let req = CodeoutRequest { path: NFC.into(), haves: vec![H.into(), W.into()], wip: true, max_bytes: 256 * MIB };
        assert_eq!(req.check(), Ok(()));
        for (bad, why) in [
            (CodeoutRequest { haves: vec![H.into(); HAVES_MAX + 1], ..req.clone() }, "257 haves"),
            (CodeoutRequest { haves: vec![H.into(), "main".into()], ..req.clone() }, "number 1"),
            (CodeoutRequest { max_bytes: 0, ..req.clone() }, "at most 0 bytes"),
            (CodeoutRequest { max_bytes: SEED_BODY_MAX + 1, ..req.clone() }, "1 to"),
            (CodeoutRequest { path: "/x/../y".into(), ..req.clone() }, "the path has"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let wip = "refs/wip/20261012T101530Z-1";
        let m = CodeoutManifest {
            v: 1,
            object_format: ObjectFormat::Sha1,
            refs: BTreeMap::from([("refs/heads/dev".to_string(), H.to_string()), (wip.to_string(), W.to_string()), (SEED_WIP_REF.to_string(), W.to_string())]),
            head: H.into(),
            branch: Some("dev".into()),
            wip_ref: Some(wip.into()),
            wip_skipped: None,
        };
        assert_eq!(m.check(), Ok(()));
        let detached = CodeoutManifest { refs: BTreeMap::from([("HEAD".to_string(), H.to_string())]), branch: None, wip_ref: None, wip_skipped: Some("over the cap".into()), ..m.clone() };
        assert_eq!(detached.check(), Ok(()));
        let with = |name: &str| {
            let mut bad = m.clone();
            bad.refs.insert(name.into(), H.into());
            bad
        };
        for (bad, why) in [
            (with("HEAD"), "outside"),
            (with("refs/tags/v1"), "outside"),
            (with("refs/remotes/origin/main"), "outside"),
            (with("refs/heads/a..b"), "outside"),
            (with("refs/wip/a b"), "outside"),
            (CodeoutManifest { wip_ref: Some("refs/wip/none".into()), ..m.clone() }, "not one of its"),
            (CodeoutManifest { wip_skipped: Some("x".into()), ..m.clone() }, "and why none"),
            (CodeoutManifest { head: "HEAD".into(), ..m.clone() }, "head that is not"),
            (CodeoutManifest { v: 0, ..m.clone() }, "v0"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let mut short = m.clone();
        short.refs.insert("refs/heads/x".into(), H[..12].to_string());
        assert!(short.check().unwrap_err().contains("target is not"));
    }

    #[test]
    fn refusal_codes_have_their_statuses() {
        let codes: BTreeSet<&str> = refusal::ALL.iter().copied().collect();
        assert_eq!(codes.len(), refusal::ALL.len(), "unique codes");
        for code in refusal::ALL {
            assert!(code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{code}");
            assert_eq!(known_refusal(code), Some(code));
        }
        let by_status = |s: u16| refusal::ALL.iter().copied().filter(|c| refusal_status(c) == s).collect::<Vec<_>>();
        assert_eq!(by_status(400), ["bad_request"]);
        assert_eq!(by_status(409), ["symlink_component", "path_occupied", "not_creatable", "other_workspace", "dirty", "diverged", "changed", "not_pristine", "busy", "not_seeded"]);
        assert_eq!(by_status(413), ["too_large"]);
        assert_eq!(by_status(422), ["bad_pack", "missing_prerequisites", "bad_refs"]);
        assert_eq!(by_status(500), ["git_failed", "transfer_failed"]);
        assert_eq!(by_status(503), ["draining"]);
        assert_eq!(by_status(504), ["timeout"]);
        assert_eq!((refusal_status("from_the_future"), known_refusal("from_the_future")), (500, None));
        assert_eq!((SeedApplied::Cloned.status(), SeedApplied::Replaced.status(), SeedApplied::UpToDate.status()), (201, 201, 200));
    }

    #[test]
    fn a_refusal_is_one_scrubbed_line() {
        let key_id = format!("{}{}", "AKIA", "Q".repeat(16));
        let r = WsRefusal::new(refusal::GIT_FAILED, &format!("git exited 128\nfatal: bad object {key_id}\n\n\x1b[31mred\n{}", "x".repeat(400)));
        assert!(r.message.starts_with("git exited 128 | fatal: bad object "), "{}", r.message);
        assert!(!r.message.contains(&key_id) && !r.message.contains('\n') && !r.message.contains('\x1b'), "{}", r.message);
        assert_eq!(r.message.chars().count(), WsRefusal::MESSAGE_MAX);
        assert!(r.message.ends_with('\u{2026}'));
        assert_eq!(r.status(), 500);
        let dirty = WsRefusal::new(refusal::DIRTY, "the checkout has changes").with_state(SeedState { tip: Some(H.into()), ..SeedState::default() });
        assert_eq!((dirty.status(), dirty.state.as_ref().and_then(|s| s.tip.as_deref())), (409, Some(H)));
        assert_eq!(WsRefusal::new(refusal::TOO_LARGE, "over its cap").with_size(7).size, Some(7));
        assert_eq!(serde_json::to_string(&WsRefusal::new("busy", "held")).unwrap(), r#"{"code":"busy","message":"held"}"#, "no state, no size: left out");
    }

    #[test]
    fn helper_heads_are_a_reply_or_a_refusal() {
        let ok: HelperHead<SeedState> = HelperHead::ok(SeedState::default(), Some(9));
        assert_eq!(serde_json::to_string(&ok).unwrap(), r#"{"ok":true,"reply":{"clean":false,"pristine":false},"len":9}"#);
        assert_eq!(ok.outcome(), Some(Ok((SeedState::default(), Some(9)))));
        let r = WsRefusal::new(refusal::SYMLINK_COMPONENT, "a component of the path is a symlink").with_size(1);
        let refused: HelperHead<SeedState> = HelperHead::refused(r.clone());
        let json = serde_json::to_string(&refused).unwrap();
        assert_eq!(json, r#"{"ok":false,"code":"symlink_component","message":"a component of the path is a symlink","size":1}"#);
        // Without `ok`, a refusing head reads as the route's refusal body.
        let body: WsRefusal = serde_json::from_str(&json.replacen(r#""ok":false,"#, "", 1)).unwrap();
        assert_eq!(body, r);
        assert_eq!(parse_head::<HelperHead<SeedState>>(json.as_bytes()).unwrap().outcome(), Some(Err(r)));
        for neither in [r#"{"ok":true}"#, r#"{"ok":false,"message":"no code"}"#] {
            assert_eq!(parse_head::<HelperHead<SeedState>>(neither.as_bytes()).unwrap().outcome(), None, "{neither}");
        }
        assert!(parse_head::<HelperHead<SeedState>>(b"not json").unwrap_err().starts_with("the head line does not parse"));
    }

    /// The helper runs as the agent: a refusing head becomes the route's
    /// refusal only through `WsRefusal::new` (a known code, one scrubbed line
    /// of at most 300 characters), so the root shim forwards nothing raw.
    #[test]
    fn a_helpers_refusal_is_normalised_before_the_route_answers_it() {
        let token = format!("{}-{}-{}-{}", "sk", "ant", "oat01", "d".repeat(60));
        let message = format!("fatal: {token}\n\x1b[2J{}", "m".repeat(2000));
        let head = format!(r#"{{"ok":false,"code":"x\u001b[2Jforged","message":{},"size":5}}"#, serde_json::to_string(&message).unwrap());
        let Some(Err(r)) = parse_head::<HelperHead<SeedState>>(head.as_bytes()).unwrap().outcome() else { panic!("a refusal") };
        assert_eq!((r.code.as_str(), r.status(), r.size), (refusal::GIT_FAILED, 500, Some(5)), "an unknown code is git_failed; the size is kept");
        assert!(r.message.chars().count() <= WsRefusal::MESSAGE_MAX && r.message.starts_with("fatal: "), "{}", r.message);
        assert!(!r.message.contains(&token) && !r.message.contains('\n') && !r.message.contains('\x1b'), "{}", r.message);
        let dirty: HelperHead<SeedState> = HelperHead { ok: false, code: Some(refusal::DIRTY.into()), message: Some("changes of its own".into()), state: Some(SeedState { tip: Some(H.into()), ..SeedState::default() }), size: None, reply: None, len: None };
        let Some(Err(r)) = dirty.outcome() else { panic!("a refusal") };
        assert_eq!((r.code.as_str(), r.status(), r.state.and_then(|s| s.tip)), (refusal::DIRTY, 409, Some(H.to_string())), "a known code and its state are kept");
    }

    #[test]
    fn framing_writes_a_line_then_the_payload_and_reads_it_back() {
        let m = manifest();
        let pack = b"PACK\x00\x00\x00\x02\nnot a line\xff".to_vec();
        let mut body = Vec::new();
        let n = write_framed(&mut body, &m, &mut pack.as_slice()).unwrap();
        assert_eq!(n as usize, body.len());
        let mut input = std::io::Cursor::new(body.clone());
        let line = read_head_line(&mut input, HEAD_LINE_MAX).unwrap();
        assert_eq!(parse_head::<SeedManifest>(&line).unwrap(), m);
        assert_eq!(line.len() + 1 + pack.len(), body.len());
        let mut rest = Vec::new();
        Read::read_to_end(&mut input, &mut rest).unwrap();
        assert_eq!(rest, pack, "the reader stops right after the line");
        assert!(!line.contains(&b'\n'));
    }

    #[test]
    fn the_head_line_reader_stops_at_its_cap_and_at_eof() {
        let at_cap = format!("{}\n", "x".repeat(9));
        assert_eq!(read_head_line(&mut at_cap.as_bytes(), 10).unwrap(), b"x".repeat(9), "a line of exactly the cap, its newline included");
        let e = read_head_line(&mut format!("{}\nrest", "x".repeat(10)).as_bytes(), 10).unwrap_err();
        assert!(e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("longer than 10 bytes"), "{e}");
        let e = read_head_line(&mut &b"{\"no\":\"newline\"}"[..], 64).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(read_head_line(&mut &b""[..], 64).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let big = SeedManifest { shallow: vec![H.into(); 2000], ..manifest() };
        assert!(head_line(&big).unwrap_err().to_string().contains(&format!("(at most {HEAD_LINE_MAX})")));
        assert!(write_framed(&mut Vec::new(), &big, &mut &b""[..]).is_err(), "nothing framed over the cap");
    }

    #[tokio::test]
    async fn the_async_head_line_reader_matches_the_blocking_one() {
        let body = format!("{}\npayload", serde_json::to_string(&manifest()).unwrap());
        let mut input = tokio::io::BufReader::new(body.as_bytes());
        let line = read_head_line_async(&mut input, HEAD_LINE_MAX).await.unwrap();
        assert_eq!(parse_head::<SeedManifest>(&line).unwrap(), manifest());
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut input, &mut rest).await.unwrap();
        assert_eq!(rest, b"payload");
        let e = read_head_line_async(&mut tokio::io::BufReader::new(&b"xxxxxxxxxxx\n"[..]), 4).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let e = read_head_line_async(&mut tokio::io::BufReader::new(&b"{}"[..]), 64).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_settings_capture_holds_its_scopes_in_order_and_the_allowlisted_keys_only() {
        let file = |scope, text: Option<&str>| SettingsFile { scope, path: "/p".into(), present: text.is_some(), size: text.map_or(0, |t| t.len() as u64), sha256: None, text: text.map(str::to_string), skipped: None };
        let c = SettingsCapture {
            path: NFC.into(),
            files: vec![file(SettingsScope::User, Some("{}")), file(SettingsScope::Project, None), file(SettingsScope::Local, Some("{\"permissions\":{}}"))],
            project: BTreeMap::from([("hasTrustDialogAccepted".to_string(), serde_json::Value::Bool(true))]),
            at: "2026-10-12T10:16:02Z".into(),
        };
        assert_eq!(c.check(), Ok(()));
        let mut swapped = c.clone();
        swapped.files.swap(0, 2);
        let mut twice = c.clone();
        twice.files[1].scope = SettingsScope::User;
        let mut wrong_size = c.clone();
        wrong_size.files[0].size = 3;
        let mut big = c.clone();
        big.files[2] = file(SettingsScope::Local, Some(&"x".repeat(SETTINGS_FILE_MAX + 1)));
        let mut key = c.clone();
        key.project.insert("mcpServers".into(), serde_json::Value::Null);
        for (bad, why) in [(swapped, "scope order"), (twice, "scope order"), (wrong_size, "for a file of 3"), (big, "at most 262144"), (key, "\"mcpServers\"")] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        assert_eq!(serde_json::to_string(&SettingsScope::ALL).unwrap(), r#"["user","project","local"]"#);
        assert_eq!(SettingsScope::ALL.map(SettingsScope::name), ["user", "project", "local"]);
    }

    #[test]
    fn the_limits_and_budgets_are_the_plans() {
        assert_eq!((SEED_BODY_MAX, CODEOUT_REQUEST_MAX), (1 << 30, 64 << 10));
        assert_eq!((SETTINGS_FILE_MAX, HAVES_MAX, HEAD_LINE_MAX, VM_PATH_MAX), (256 << 10, 256, 64 << 10, 4096));
        assert_eq!((CODE_PORT, APP_PORT), (9418, 8080));
        let secs = [budget::SEED_STATE, budget::SEED_CLONE, budget::SEED_UPDATE, budget::CODEOUT, budget::SUSPEND_SNAPSHOT, budget::TRANSCRIPT, budget::SETTINGS, budget::BUSY_WAIT].map(|d| d.as_secs());
        assert_eq!(secs, [30, 600, 180, 120, 8, 60, 10, 30], "plan §6's budgets");
    }

    /// S9 (plans/s9-contracts.md §1.5): the git routes' and the transfers'
    /// caps and budgets, and what they are sized for: a pull's URLs fit its
    /// body, a view's and a subtree stat's JSON fit the payload.
    #[test]
    fn the_s9_limits_and_budgets_are_the_plans() {
        use crate::wire::s3::{PRESIGNED_URL_MAX, PULL_PARTS_MAX};
        use crate::wire::view::{VIEW_FILE_MAX, VIEW_ID_MAX, VIEW_MESSAGES_MAX, VIEW_META_MAX, VIEW_TITLE_MAX};
        assert_eq!((GIT_REQUEST_MAX, GIT_RESPONSE_MAX, GIT_CGI_HEAD_MAX, GIT_CGI_MAX), (1 << 20, 1 << 30, 16 << 10, 2));
        assert_eq!((TRANSFER_REQUEST_MAX, TRANSFERS_MAX, PULL_MAX, SUBTREE_FILES_MAX, SUBTREE_BYTES_MAX, JSON_PAYLOAD_MAX), (640 << 10, 4, 4 << 30, 256, 256 << 20, 2 << 20));
        let secs = [budget::GIT_ADVERTISE, budget::GIT_UPLOAD_PACK, budget::TRANSCRIPT_PUSH, budget::TRANSCRIPT_PULL, budget::TRANSCRIPT_VIEW, budget::TRANSCRIPT_TAIL].map(|d| d.as_secs());
        assert_eq!(secs, [30, 600, 60, 60, 30, 8]);
        assert_eq!(budget::TRANSCRIPT.as_secs(), 60, "the extended stat keeps S8's");
        // A pull of every part at the longest URL, with its JSON and a rel, fits one body.
        const { assert!(PULL_PARTS_MAX * (PRESIGNED_URL_MAX + 256) + REL_MAX + 1024 <= TRANSFER_REQUEST_MAX) };
        // A view: its text escaped at most 6 bytes per byte, plus every capped field of every message.
        const { assert!(VIEW_FILE_MAX * 6 + VIEW_MESSAGES_MAX as usize * (2 * VIEW_ID_MAX * 6 + 256) + (VIEW_TITLE_MAX * 4 + 2 * VIEW_META_MAX) * 6 + 1024 < 1_700_000) };
        const { assert!(1_700_000 <= JSON_PAYLOAD_MAX) };
        // A subtree stat: every file's rel, size and sha256.
        const { assert!(SUBTREE_FILES_MAX * (REL_MAX + 64 + 64) < 1_200_000 && 1_200_000 <= JSON_PAYLOAD_MAX) };
        assert!(GIT_UPLOAD_PACK_ROUTE.starts_with(GIT_REPO_PREFIX) && GIT_INFO_REFS_ROUTE == format!("{GIT_REPO_PREFIX}{GIT_PATH_INFO_REFS}"));
        assert_eq!(GIT_UPLOAD_PACK_ROUTE, format!("{GIT_REPO_PREFIX}{GIT_PATH_INFO_UPLOAD_PACK}"));
        assert!(NO_SUCH_ROUTE.ends_with('\n') && GIT_RECEIVE_PACK_REFUSAL.starts_with("ai-env: receive-pack is refused"));
        assert!(GIT_PROTOCOLS.contains(&GIT_PROTOCOL_V2) && GIT_CGI_HEADERS.iter().all(|h| h.bytes().all(|b| !b.is_ascii_uppercase())));
    }

    /// `tests/fixtures/wire/codeport-golden.json`: one document per wire
    /// type and shape, each read back into its type and written again byte
    /// for byte (field order, left-out fields, enum spellings); every one the
    /// validators judge passes them.
    #[test]
    fn golden_codeport_documents_round_trip_byte_identically() {
        fn again<T: Serialize + DeserializeOwned>(raw: &str) -> String {
            serde_json::to_string(&serde_json::from_str::<T>(raw).unwrap_or_else(|e| panic!("{e}: {raw}"))).unwrap()
        }
        /// Read a document back into its type and write it again.
        type RoundTrip = fn(&str) -> String;
        let text = include_str!("../../tests/fixtures/wire/codeport-golden.json");
        let all: BTreeMap<String, Box<RawValue>> = serde_json::from_str(text).unwrap();
        let cases: [(&str, RoundTrip); 38] = [
            ("path_query", again::<PathQuery>),
            ("rel_query", again::<RelQuery>),
            ("seed_query_clone", again::<SeedQuery>),
            ("seed_query_update_detached", again::<SeedQuery>),
            ("seed_manifest_dirty", again::<SeedManifest>),
            ("seed_manifest_clean_detached_sha256", again::<SeedManifest>),
            ("seed_state_unseeded", again::<SeedState>),
            ("seed_state_seeded", again::<SeedState>),
            ("seed_reply_cloned", again::<SeedReply>),
            ("seed_reply_up_to_date", again::<SeedReply>),
            ("codeout_request", again::<CodeoutRequest>),
            ("codeout_manifest", again::<CodeoutManifest>),
            ("codeout_manifest_detached_skipped", again::<CodeoutManifest>),
            ("transcript_stat_absent", again::<TranscriptStat>),
            ("transcript_stat_present", again::<TranscriptStat>),
            ("settings_capture", again::<SettingsCapture>),
            ("refusal_symlink_component", again::<WsRefusal>),
            ("refusal_dirty", again::<WsRefusal>),
            ("helper_head_seed_state", again::<HelperHead<SeedState>>),
            ("helper_head_codeout", again::<HelperHead<CodeoutManifest>>),
            ("helper_head_refused", again::<HelperHead<SeedReply>>),
            ("snapshot_reply", again::<SnapshotReply>),
            ("workspace_view", again::<WorkspaceView>),
            // S9 (plans/s9-contracts.md §1.9).
            ("stat_query_from", again::<StatQuery>),
            ("transcript_stat_from", again::<TranscriptStat>),
            ("transcript_push", again::<TranscriptPush>),
            ("transcript_push_reply", again::<TranscriptPushReply>),
            ("transcript_pull", again::<TranscriptPull>),
            ("transcript_pull_reply_written", again::<TranscriptPullReply>),
            ("transcript_pull_reply_bad_part", again::<TranscriptPullReply>),
            ("view_query", again::<ViewQuery>),
            ("transcript_view_reply", again::<crate::wire::view::TranscriptViewReply>),
            ("transcript_tail", again::<TranscriptTail>),
            ("refusal_transfer_failed", again::<WsRefusal>),
            ("helper_head_transcript_read", again::<HelperHead<TranscriptReadReply>>),
            ("helper_head_transcript_write", again::<HelperHead<TranscriptWriteReply>>),
            ("helper_head_git_cgi", again::<HelperHead<GitCgiReply>>),
            ("helper_head_json_payload", again::<HelperHead<JsonPayloadReply>>),
        ];
        let names: BTreeSet<&str> = cases.iter().map(|(n, _)| *n).collect();
        assert_eq!(all.keys().map(String::as_str).collect::<BTreeSet<_>>(), names, "one case per document");
        for (name, round_trip) in cases {
            let raw = all[name].get();
            assert_eq!(round_trip(raw), raw, "{name}: not byte-identical once re-serialised");
        }
        let doc = |name: &str| all[name].get();
        assert_eq!(vm_path_check(&serde_json::from_str::<PathQuery>(doc("path_query")).unwrap().path), Ok(()));
        assert_eq!(transcript_rel_check(&serde_json::from_str::<RelQuery>(doc("rel_query")).unwrap().rel), Ok(()));
        for name in ["seed_query_clone", "seed_query_update_detached"] {
            assert_eq!(serde_json::from_str::<SeedQuery>(doc(name)).unwrap().check(), Ok(()), "{name}");
        }
        for name in ["seed_manifest_dirty", "seed_manifest_clean_detached_sha256"] {
            assert_eq!(serde_json::from_str::<SeedManifest>(doc(name)).unwrap().check(), Ok(()), "{name}");
        }
        assert_eq!(serde_json::from_str::<CodeoutRequest>(doc("codeout_request")).unwrap().check(), Ok(()));
        for name in ["codeout_manifest", "codeout_manifest_detached_skipped"] {
            assert_eq!(serde_json::from_str::<CodeoutManifest>(doc(name)).unwrap().check(), Ok(()), "{name}");
        }
        assert_eq!(serde_json::from_str::<SettingsCapture>(doc("settings_capture")).unwrap().check(), Ok(()));
        for name in ["refusal_symlink_component", "refusal_dirty"] {
            let r: WsRefusal = serde_json::from_str(doc(name)).unwrap();
            assert_eq!((known_refusal(&r.code).is_some(), r.status()), (true, 409), "{name}");
        }
        let in_head: CodeoutManifest = serde_json::from_str(doc("helper_head_codeout")).map(|h: HelperHead<CodeoutManifest>| h.reply.unwrap()).unwrap();
        assert_eq!(in_head.check(), Ok(()));
        let unseeded: SeedState = serde_json::from_str(doc("seed_state_unseeded")).unwrap();
        assert_eq!(unseeded, SeedState::default());
        // S9: every request passes its check; the new refusal is a 500; the payload head names its payload.
        assert_eq!(serde_json::from_str::<StatQuery>(doc("stat_query_from")).unwrap().check(), Ok(()));
        assert_eq!(serde_json::from_str::<TranscriptPush>(doc("transcript_push")).unwrap().check(), Ok(()));
        assert_eq!(serde_json::from_str::<TranscriptPull>(doc("transcript_pull")).unwrap().check(), Ok(()));
        assert_eq!(serde_json::from_str::<ViewQuery>(doc("view_query")).unwrap().check(), Ok(()));
        assert_eq!(serde_json::from_str::<TranscriptTail>(doc("transcript_tail")).unwrap().check(), Ok(()));
        let view: crate::wire::view::TranscriptViewReply = serde_json::from_str(doc("transcript_view_reply")).unwrap();
        assert_eq!(view.check(10), Ok(()));
        let r: WsRefusal = serde_json::from_str(doc("refusal_transfer_failed")).unwrap();
        assert_eq!((known_refusal(&r.code), r.status()), (Some(refusal::TRANSFER_FAILED), 500));
        let payload = doc("transcript_view_reply").as_bytes();
        let head: HelperHead<JsonPayloadReply> = serde_json::from_str(doc("helper_head_json_payload")).unwrap();
        assert_eq!((head.len, head.reply.map(|r| r.sha256)), (Some(payload.len() as u64), Some(sha256_hex(payload))), "the payload head names §6.1's example");
        let stat: TranscriptStat = serde_json::from_str(doc("transcript_stat_from")).unwrap();
        assert_eq!((stat.sha256, stat.end_fp.as_deref(), stat.subtree.len()), (None, Some(D_ALL), 1), "no whole-file sha256 with from");
        let push: TranscriptPush = serde_json::from_str(doc("transcript_push")).unwrap();
        assert!(!format!("{push:?}").contains("X-Amz-Signature"), "a URL is never printed");
    }

    /// The four digests of §1.9's documents: `[0, 48213)`, `[48213, 52000)`, the whole 52000 bytes, the subagent file.
    const D_BASE: &str = "841075eede78b44b2d2862f4c38a643daf938671983e4ca0563a98a82ceddcd1";
    const D_SEGMENT: &str = "b094ab054161cac4f8714d6855dc32bf0488f8eed1c4790aec8f054577f7c5c2";
    const D_ALL: &str = "756ad326b9d0e363b1359566e1992e0bcdaa19c4939f0c7ad890dcfea3f9fd4a";
    const D_FILE: &str = "d569b20cbdd570395fd77fa48b21cf76be5842248a2b7571ea17204e6b907e59";

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(bytes))
    }

    /// A presigned URL of the lab-free bucket for `key`, signed over
    /// `signed`, `extra` query parameters first (built at run time).
    fn presigned(key: &str, extra: &str, signed: &str) -> PresignedUrl {
        let credential = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z";
        let url = format!("https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/{key}?{extra}{credential}&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={}", signed.replace(';', "%3B"), "e".repeat(64));
        PresignedUrl::new(url).unwrap()
    }

    /// Each transfer's URL must fit its bytes: a push of the main transcript
    /// writes the segment at `from` or a base from 0, a subtree file its own
    /// sha256's `File`; a tail the tail at `from`; a pull part a key of the
    /// rel's session; never another session's, the Mac's own (a push) or the
    /// egress check's; the op's signed headers exactly; no query beyond the
    /// signature's but a pull part's `versionId`.
    #[test]
    fn transfer_requests_refuse_a_key_that_does_not_fit_their_bytes() {
        let rel = format!("{SLUG}/{ID}.jsonl");
        let sub = format!("{SLUG}/{ID}/subagents/agent-a1.jsonl");
        let other = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
        let seg = format!("v1/{ID}/vm/g1/s/000000000000bc55");
        let push = TranscriptPush { rel: rel.clone(), from: 48213, len: 3787, sha256: D_SEGMENT.into(), url: presigned(&seg, "", SIGNED_HEADERS_PUT), owner: "123456789012".into(), proxy: Some("http://10.42.0.10:3128".into()) };
        assert_eq!(push.check(), Ok(()));
        let base = TranscriptPush { from: 0, url: presigned(&format!("v1/{ID}/vm/g2/base"), "", SIGNED_HEADERS_PUT), ..push.clone() };
        assert_eq!(base.check(), Ok(()));
        let file = TranscriptPush { rel: sub.clone(), from: 0, sha256: D_FILE.into(), url: presigned(&format!("v1/{ID}/vm/f/{D_FILE}"), "", SIGNED_HEADERS_PUT), ..push.clone() };
        assert_eq!(file.check(), Ok(()));
        for (bad, why) in [
            (TranscriptPush { from: 48212, ..push.clone() }, "does not fit"),
            (TranscriptPush { from: 1, ..base.clone() }, "does not fit"),
            (TranscriptPush { rel: sub.clone(), ..push.clone() }, "does not fit"),
            (TranscriptPush { rel: rel.clone(), ..file.clone() }, "does not fit"),
            (TranscriptPush { sha256: D_BASE.into(), ..file.clone() }, "does not fit"),
            (TranscriptPush { url: presigned(&format!("v1/{other}/vm/g1/s/000000000000bc55"), "", SIGNED_HEADERS_PUT), ..push.clone() }, "does not fit"),
            (TranscriptPush { url: presigned(&format!("v1/{ID}/mac/{D_SEGMENT}"), "", SIGNED_HEADERS_PUT), ..push.clone() }, "does not fit"),
            (TranscriptPush { url: presigned(&format!("v1/{ID}/vm/g1/t/000000000000bc55"), "", SIGNED_HEADERS_PUT), ..push.clone() }, "does not fit"),
            (TranscriptPush { url: presigned("v1/_egress-check/abcd1234", "", SIGNED_HEADERS_PUT), ..push.clone() }, "does not fit"),
            (TranscriptPush { url: presigned("x/_egress-check/abcd1234", "", SIGNED_HEADERS_PUT), ..push.clone() }, "does not fit"),
            (TranscriptPush { url: presigned("", "", SIGNED_HEADERS_PUT), ..push.clone() }, "names no object"),
            (TranscriptPush { url: presigned(&seg, "", SIGNED_HEADERS_GET), ..push.clone() }, "signed over other headers"),
            (TranscriptPush { url: presigned(&seg, "versionId=fv1&", SIGNED_HEADERS_PUT), ..push.clone() }, "carrying versionId"),
            (TranscriptPush { url: presigned(&seg, "partNumber=1&uploadId=fu1&", SIGNED_HEADERS_PUT), ..push.clone() }, "carrying partNumber"),
            (TranscriptPush { len: 0, ..push.clone() }, "pushes 0 bytes"),
            (TranscriptPush { len: PUSH_MAX + 1, ..push.clone() }, "(1 to 4294967296)"),
            (TranscriptPush { sha256: D_SEGMENT.to_uppercase(), ..push.clone() }, "sha256 that is not"),
            (TranscriptPush { owner: "12345678901".into(), ..push.clone() }, "bucket owner"),
            (TranscriptPush { proxy: Some("http://8.8.8.8:3128".into()), ..push.clone() }, "the proxy"),
            (TranscriptPush { rel: format!("{SLUG}/x.jsonl"), ..push.clone() }, "the transcript's rel"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
            assert!(!e.contains(&"e".repeat(64)), "never the signature: {e}");
        }
        let part = |key: &str, extra: &str, sha: Option<&str>| PullPart { url: presigned(key, extra, SIGNED_HEADERS_GET), len: 10, sha256: sha.map(str::to_string) };
        let pull = TranscriptPull {
            rel: rel.clone(),
            parts: vec![part(&format!("v1/{ID}/mac/{D_BASE}"), "versionId=fv1&", Some(D_BASE)), part(&seg, "versionId=fv2&", Some(D_SEGMENT)), part(&format!("v1/{ID}/vm/g1/t/000000000000cb20"), "", None)],
            sha256: Some(D_ALL.into()),
            owner: "123456789012".into(),
            proxy: None,
        };
        assert_eq!(pull.check(), Ok(()));
        for (bad, why) in [
            (TranscriptPull { parts: vec![part(&format!("v1/{other}/vm/g1/base"), "", Some(D_BASE))], ..pull.clone() }, "not of the rel's session"),
            (TranscriptPull { parts: vec![part("v1/_egress-check/abcd1234", "", Some(D_BASE))], ..pull.clone() }, "not of the rel's session"),
            (TranscriptPull { parts: vec![part(&seg, "", None)], ..pull.clone() }, "no tail"),
            (TranscriptPull { parts: vec![part(&seg, "uploadId=fu1&", Some(D_SEGMENT))], ..pull.clone() }, "carrying uploadId"),
            (TranscriptPull { parts: vec![PullPart { url: presigned(&seg, "", SIGNED_HEADERS_PUT), len: 1, sha256: Some(D_SEGMENT.into()) }], ..pull.clone() }, "signed over other headers"),
            (TranscriptPull { parts: Vec::new(), ..pull.clone() }, "pulls 0 parts"),
            (TranscriptPull { parts: vec![part(&seg, "", Some(D_SEGMENT)); PULL_PARTS_MAX + 1], ..pull.clone() }, "pulls 129 parts"),
            (TranscriptPull { parts: vec![PullPart { len: PULL_MAX + 1, ..part(&seg, "", Some(D_SEGMENT)) }], ..pull.clone() }, "in all"),
            (TranscriptPull { sha256: Some("x".into()), ..pull.clone() }, "sha256 that is not"),
            // A tail is only ever the main transcript's (S9 §13, I2): never part of another file.
            (TranscriptPull { rel: sub.clone(), parts: vec![part(&format!("v1/{ID}/vm/f/{D_FILE}"), "", Some(D_FILE)), part(&format!("v1/{ID}/vm/g1/t/0000000000001000"), "", None)], sha256: None, ..pull.clone() }, "a tail (part number 1) into a rel that is not"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
        assert_eq!(TranscriptPull { rel: sub.clone(), parts: vec![part(&format!("v1/{ID}/vm/f/{D_FILE}"), "", Some(D_FILE))], sha256: Some(D_FILE.into()), ..pull.clone() }.check(), Ok(()), "a subtree file's own key");
        let tail = TranscriptTail { rel: rel.clone(), from: 52000, url: presigned(&format!("v1/{ID}/vm/g1/t/000000000000cb20"), "", SIGNED_HEADERS_TAIL), owner: "123456789012".into(), proxy: None, expires_at: 1_792_235_730 };
        assert_eq!(tail.check(), Ok(()));
        for (bad, why) in [
            (TranscriptTail { rel: sub.clone(), ..tail.clone() }, "a tail is only ever the session's main transcript"),
            (TranscriptTail { rel: sub.clone(), from: 0, url: presigned(&format!("v1/{ID}/vm/g1/t/0000000000000000"), "", SIGNED_HEADERS_TAIL), ..tail.clone() }, "is not <slug>/<uuid>.jsonl"),
            (TranscriptTail { from: 52001, ..tail.clone() }, "not the tail at from"),
            (TranscriptTail { url: presigned(&seg, "", SIGNED_HEADERS_TAIL), ..tail.clone() }, "not the tail at from"),
            (TranscriptTail { url: presigned(&format!("v1/{ID}/vm/g1/t/000000000000cb20"), "", SIGNED_HEADERS_PUT), ..tail.clone() }, "signed over other headers"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
        let q = StatQuery { rel: rel.clone(), from: Some(48213), fp: Some(D_BASE.into()), subtree: true };
        assert_eq!(q.check(), Ok(()));
        assert_eq!(q.pairs(), vec![("rel", rel.clone()), ("from", "48213".to_string()), ("fp", D_BASE.to_string()), ("subtree", "true".to_string())]);
        assert_eq!(StatQuery { rel: rel.clone(), from: None, fp: None, subtree: false }.pairs(), vec![("rel", rel.clone())]);
        for (bad, why) in [
            (StatQuery { from: None, ..q.clone() }, "without from"),
            (StatQuery { fp: Some("ab".into()), ..q.clone() }, "64 lowercase hex"),
            (StatQuery { rel: sub.clone(), ..q.clone() }, "subtree of a rel"),
        ] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
        let v = ViewQuery { rel: rel.clone(), n: 10 };
        assert_eq!((v.check(), v.pairs()), (Ok(()), vec![("rel", rel.clone()), ("n", "10".to_string())]));
        for (bad, why) in [(ViewQuery { n: 0, ..v.clone() }, "0 messages"), (ViewQuery { n: 51, ..v.clone() }, "51 messages"), (ViewQuery { rel: sub, ..v.clone() }, "the view of a rel")] {
            let e = bad.check().unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
    }
}
