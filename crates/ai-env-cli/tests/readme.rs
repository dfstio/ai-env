//! S8 §13: the doc-test. The fenced `sh doc-test` blocks of the README's
//! "Cursor in a MicroVM (stage S8)" section, of its S9 section ([`S9_SECTION`]),
//! of its S10 section ([`S10_SECTION`]) and of `skills/ai-env/SKILL.md`
//! run in their dry forms ([`DRY_FORMS`] is the specification) against a
//! planted HOME: S7's green world (the sealed runtime key and setup-token,
//! the egress record, the fake age), the file-backed fake API with one VM
//! started by `vm run`, a registered remote session, a fixture repository
//! with uncommitted changes, a logging fake git before the real one, and
//! fakes for the tools that must not run (`aws`, `claude` and the doctor's
//! others). The data plane goes to a stand-in endpoint on loopback, which
//! answers a code-out's manifest and nothing else: nothing reaches AWS,
//! Anthropic or the network. The documented commands unseal the runtime key
//! as they would against AWS (`AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL`), so each
//! Touch ID reaches the fake age's log. Each command is judged against its
//! row: its exit and stdout; its stderr (no warning, and after exit 0 no
//! `ai-env:` line but the planted world's own, [`worlds_own`]); its Touch
//! IDs (the fake age's decrypts: one each for `box fetch --dry-run`,
//! `vm list` and `vm gc`, none for the others, `box seed --dry-run` and
//! `vm warm --dry-run` among them, and no seal); its calls to the fake API
//! (none, reads, or reads and a code-port token for `box fetch --dry-run`);
//! the refused tools it ran (the doctor's probes only); and the HOME tree,
//! which it changes only as a dry run may ([`allowed_change`], [`content`]),
//! its audit log only by appending the rows its row names (S9: `box review`
//! audits each review, [`audit_problems`]). Afterwards the endpoint saw
//! code-out reads only, and the fixture repository's refs, index, status and
//! files are unchanged (no pre-push hook written either). Beside it: the
//! Commands block parses (`--help`), the VM's CLAUDE.md in the README is
//! `image/claude/CLAUDE.md` byte for byte, every JSON block parses, every
//! `ai-env` command of the two S8 sections and of the S9 and S10 sections
//! is doc-tested, the S10 section quotes the wrapper's notes and lines as
//! the code writes them and shows `[vm]`'s S10 keys at their defaults, and
//! the engine refuses what it must. In `make test` (the default and bridge
//! worlds) and `make doc-test`. Built in S8 wave 2 (W9); the S9 section and
//! its rows in S9 wave 2 (G9); the S10 section in S10 wave 2 (D).
//!
//! A doc-test line is one `ai-env` command, optionally followed by two
//! spaces and a `#` comment. Words split on whitespace, single and double
//! quotes honoured; shell syntax outside quotes ([`META`]) and what zsh
//! expands inside double quotes are refused, so every command is zsh-safe
//! as written. The comment is for reading and is not checked: pasting it
//! into zsh needs `setopt interactive_comments`. The placeholders
//! [`PLACEHOLDERS`] are filled in from the planted world; any other
//! all-capitals word fails.
mod common;
// S7's green world: `common` has it with the shim feature; the bridge-only world includes it here.
#[cfg(feature = "shim")]
use common::green_world;
#[cfg(not(feature = "shim"))]
#[path = "common/green_world.rs"]
mod green_world;

use ai_env_cli::bridge::api::{Call, FakeState};
use ai_env_cli::bridge::config::{BridgeConfig, Paths, VmCfg};
use ai_env_cli::bridge::registry::{self, SessionRow};
use ai_env_cli::bridge::remote::link::{LossCause, MigrateTrigger, MoveKind};
use ai_env_cli::bridge::remote::{self, Failure, StayedThen};
use ai_env_cli::bridge::settings_capture::{capture_path, CapturePhase};
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::wire::frame::{CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1};
use ai_env_cli::wire::workspace::{head_line, CodeoutManifest, ObjectFormat, SeedManifest, SettingsCapture, SettingsFile, SettingsScope, CODE_PORT};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The repository's root: the README, SKILL.md and the image's files are read there.
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
/// The README's S8 section, by its heading.
const SECTION: &str = "### Cursor in a MicroVM (stage S8)";
/// The README's S9 section, by its heading.
const S9_SECTION: &str = "### Pushes reviewed, transcripts in S3 (stage S9)";
/// The README's S10 section, by its heading.
const S10_SECTION: &str = "### Chats move to a new VM, idle chats park (stage S10)";
/// The bridge's audit log, relative to the planted HOME: a documented command
/// may only append to it, and only the rows its [`DryForm::audits`] names.
const AUDIT_LOG: &str = "bridge/audit.jsonl";
/// SKILL.md's MicroVM section, by its heading.
const SKILL_SECTION: &str = "## MicroVM sessions (ai-env bridge)";
/// The info string of a block the doc-test runs (GitHub reads its first word only, and highlights it as `sh`).
const DOC_TEST: &str = "sh doc-test";
/// The info string of the README's copy of the VM's CLAUDE.md.
const VM_CLAUDE_MD: &str = "text vm-claude-md";
/// Every wait here: one command, one request to the stand-in endpoint.
const LIMIT: Duration = Duration::from_secs(60);
/// The placeholders a doc-test line may hold, filled in from the planted world.
const PLACEHOLDERS: [&str; 4] = ["WORKSPACE", "UUID", "ID", "BRANCH"];
/// What a word may not hold outside quotes: shell syntax (plans/s8-design-tests.md §3.5's
/// list, and the brackets, braces, parentheses, `~`, `!` and `\` beside it).
const META: [char; 18] = ['$', '`', '|', ';', '&', '>', '<', '*', '?', '[', ']', '(', ')', '{', '}', '~', '!', '\\'];
/// What a double-quoted word may not hold: zsh expands these there.
const META_IN_DOUBLE: [char; 4] = ['$', '`', '\\', '!'];
/// The fixture repository's branch (`BRANCH`).
const BRANCH: &str = "main";
/// The image version the green world's egress check is recorded for (the fake's one version).
const IMAGE_VERSION: &str = "1.0";

/// How a documented command is made dry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dry {
    /// Dry without this flag: it is dropped.
    Drop(&'static str),
    /// Dry with this flag: it is added unless the line has it.
    Add(&'static str),
    /// Read-only as written.
    AsIs,
}

/// What a documented command may ask of the control plane: every call the
/// fake API records during its run must be one its row allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Api {
    /// No call at all.
    None,
    /// Reads only: a listing, a `GetMicrovm`, an image's, the connector's, a `/health`.
    Reads,
    /// Reads, and a code-port token minted for one (`box fetch --dry-run`
    /// reads the VM's refs, plans/s8-plan.md §7).
    ReadsAndMint,
}

impl Api {
    /// Whether the row allows `call`; a call this list does not know is no read.
    fn allows(self, call: &Call) -> bool {
        let read = matches!(call, Call::Get(_) | Call::List(_) | Call::GetImage(_) | Call::ListImageVersions(_) | Call::ListImages | Call::GetConnector(_) | Call::Health { .. } | Call::HealthDetail { .. });
        match self {
            Api::None => false,
            Api::Reads => read,
            Api::ReadsAndMint => read || matches!(call, Call::Token { port, .. } if *port == CODE_PORT),
        }
    }
}

/// One row of [`DRY_FORMS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DryForm {
    /// The command's words after `ai-env`.
    cmd: &'static [&'static str],
    /// How it is made dry.
    dry: Dry,
    /// The exit codes it may end with.
    codes: &'static [i32],
    /// What its stdout must hold, one of (none named: nothing).
    says: &'static [&'static str],
    /// The Touch IDs it asks for: the fake age's decrypts during its run, exactly.
    unseals: u8,
    /// What it may ask of the control plane.
    api: Api,
    /// Whether it may run the refused tools ([`REFUSED_TOOLS`]): the doctor's probes.
    tools: bool,
    /// The audit rows it may append to [`AUDIT_LOG`], by event (none unless [`DryForm::audited`] names them).
    audits: &'static [&'static str],
}

impl DryForm {
    const fn new(cmd: &'static [&'static str], dry: Dry, codes: &'static [i32], says: &'static [&'static str], unseals: u8, api: Api, tools: bool) -> DryForm {
        DryForm { cmd, dry, codes, says, unseals, api, tools, audits: &[] }
    }

    /// The row, allowed to append these audit events (a read-only command that audits itself: `box review`).
    const fn audited(self, events: &'static [&'static str]) -> DryForm {
        DryForm { audits: events, ..self }
    }
}

/// Every command a doc-test block may hold (plans/s8-plan.md §13: this
/// table is the specification): a command not listed here fails the
/// doc-test. A row names the command, how it is made dry, its exits, what
/// its stdout names, its Touch IDs, what it may ask of the control plane,
/// and whether it may run the refused tools. The three that reach AWS cost
/// one Touch ID each, the runtime key's unseal: `box fetch --dry-run` mints
/// a code-port token to read the VM's refs, and `vm list` and `vm gc` list
/// the VMs (S10 L12: `vm list` also runs gc's local reconcile, which audits
/// `vm_gc_reconcile` and stamps `state/gc.stamp`); `box seed --dry-run` and `vm warm --dry-run` reach neither AWS
/// nor age. S9's: `box review` is read-only as written (no AWS, no Touch ID;
/// it audits each review, `box_review`), `box hook-install --dry-run` writes
/// no hook, and `session gc --remote` and `session migrate-s9` without
/// `--yes` list from the Mac's own files (no S3 read, no Touch ID). Not
/// listed on purpose: `vm status` and `vm health` (they rewrite the VM's
/// row), `vm terminate`, `vm exec`, `egress check`, `session stage`,
/// `session sync`, `session forget` and S10's `session migrate` (no dry
/// form: it moves the chat, and with no wrapper unseals and starts a VM).
/// `box fetch --smart-http` stays out of the blocks: the stand-in endpoint
/// answers a code-out's manifest and speaks no git smart-HTTP.
const DRY_FORMS: [DryForm; 20] = [
    DryForm::new(&["wrapper", "install"], Dry::Drop("--write"), &[0], &["dry run"], 0, Api::None, false),
    DryForm::new(&["wrapper", "uninstall"], Dry::Drop("--write"), &[0], &["nothing to remove", "dry run"], 0, Api::None, false),
    DryForm::new(&["wrapper", "status"], Dry::AsIs, &[0], &["claudeCode.claudeProcessWrapper"], 0, Api::None, false),
    DryForm::new(&["wrapper", "settings-sync"], Dry::Drop("--write"), &[0], &[], 0, Api::None, false),
    DryForm::new(&["vm", "gc"], Dry::Drop("--yes"), &[0], &[], 1, Api::Reads, false),
    DryForm::new(&["creds", "forget"], Dry::Drop("--yes"), &[0], &[], 0, Api::None, false),
    DryForm::new(&["box", "seed"], Dry::Add("--dry-run"), &[0], &["nothing was sent", "\"dry_run\": true"], 0, Api::None, false),
    DryForm::new(&["box", "fetch"], Dry::Add("--dry-run"), &[0], &["nothing was fetched", "nothing to fetch", "\"dry_run\": true"], 1, Api::ReadsAndMint, false),
    DryForm::new(&["vm", "warm"], Dry::Add("--dry-run"), &[0], &["nothing was started", "\"dry_run\": true"], 0, Api::None, false),
    DryForm::new(&["doctor"], Dry::AsIs, &[0, 1], &[], 0, Api::None, true),
    DryForm::new(&["creds", "status"], Dry::AsIs, &[0], &[], 0, Api::None, false),
    DryForm::new(&["session", "list"], Dry::AsIs, &[0], &[], 0, Api::None, false),
    DryForm::new(&["session", "show"], Dry::AsIs, &[0], &[], 0, Api::None, false),
    DryForm::new(&["wrapper", "census"], Dry::AsIs, &[0], &[], 0, Api::None, false),
    DryForm::new(&["vm", "list"], Dry::AsIs, &[0], &[], 1, Api::Reads, false).audited(&["vm_gc_reconcile"]),
    DryForm::new(&["lab", "list"], Dry::AsIs, &[0], &[], 0, Api::None, false),
    DryForm::new(&["box", "review"], Dry::AsIs, &[0], &["box review: pass", "\"verdict\": \"pass\""], 0, Api::None, false).audited(&["box_review"]),
    DryForm::new(&["box", "hook-install"], Dry::Add("--dry-run"), &[0], &["nothing was written", "\"would_install\""], 0, Api::None, false),
    DryForm::new(&["session", "gc"], Dry::Drop("--yes"), &[0], &["nothing removed", "no S3 transcript", "\"dry_run\": true"], 0, Api::None, false),
    DryForm::new(&["session", "migrate-s9"], Dry::Drop("--yes"), &[0], &["nothing migrated", "no S8 mirror", "\"dry_run\": true"], 0, Api::None, false),
];

/// Flags that make a listed command act (a Touch ID, a probe row): refused on any line.
const ACTING_FLAGS: [&str; 2] = ["--unseal", "--record-probes"];

/// The tools the planted `PATH` holds as fakes that must not run (`tests/fakes/logged.sh`:
/// each call logged, exit 1), so the doctor never finds the real ones (it also looks in
/// `/opt/homebrew/bin`).
const REFUSED_TOOLS: [&str; 8] = ["aws", "claude", "rustup", "cargo-lambda", "zig", "pulumi", "docker", "curl"];

// ---- the engine --------------------------------------------------------------------------

/// One fenced code block: its info string, the number of its first line
/// (1-based, the one after the opening fence) and its lines, the fence's
/// indentation removed.
#[derive(Debug, Clone)]
struct Block {
    info: String,
    first: usize,
    lines: Vec<String>,
}

impl Block {
    /// The block's text: each line and its newline.
    fn text(&self) -> String {
        self.lines.iter().map(|l| format!("{l}\n")).collect()
    }
}

/// The fenced code blocks of `md` (backtick fences of three or more,
/// indented at most three spaces; closed by a fence at least as long).
fn blocks(md: &str) -> Vec<Block> {
    let mut out = Vec::new();
    // The open block: its fence's length and indentation, and the block.
    let mut open: Option<(usize, usize, Block)> = None;
    for (i, line) in md.lines().enumerate() {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let rest = &line[indent..];
        let ticks = rest.len() - rest.trim_start_matches('`').len();
        let fence = indent <= 3 && ticks >= 3;
        match open.take() {
            None if fence => open = Some((ticks, indent, Block { info: rest[ticks..].trim().to_string(), first: i + 2, lines: Vec::new() })),
            None => {}
            Some((len, _, block)) if fence && ticks >= len && rest[ticks..].trim().is_empty() => out.push(block),
            Some((len, fence_indent, mut block)) => {
                block.lines.push(line[indent.min(fence_indent)..].to_string());
                open = Some((len, fence_indent, block));
            }
        }
    }
    out
}

/// The part of `md` from the line `heading` to the next heading of its
/// level or above outside a code block, and its first line's number.
fn section<'a>(md: &'a str, heading: &str) -> Option<(usize, &'a str)> {
    let level = heading.len() - heading.trim_start_matches('#').len();
    let mut start: Option<(usize, usize)> = None;
    let mut offset = 0;
    let mut fenced = false;
    for (i, line) in md.split_inclusive('\n').enumerate() {
        let bare = line.trim_end_matches('\n');
        if bare.trim_start().starts_with("```") {
            fenced = !fenced;
        } else if !fenced {
            match start {
                None if bare == heading => start = Some((i + 1, offset)),
                Some((first, from)) => {
                    let hashes = bare.len() - bare.trim_start_matches('#').len();
                    if (1..=level).contains(&hashes) && bare[hashes..].starts_with(' ') {
                        return Some((first, &md[from..offset]));
                    }
                }
                None => {}
            }
        }
        offset += line.len();
    }
    start.map(|(first, from)| (first, &md[from..]))
}

/// One command of a doc-test block, where it is and as written.
#[derive(Debug, Clone)]
struct DocLine {
    /// `README.md:812`.
    at: String,
    text: String,
}

/// The lines of the `sh doc-test` blocks of `md` (blank lines skipped),
/// `md` starting at line `first` of `file`.
fn doc_lines(md: &str, file: &str, first: usize) -> Vec<DocLine> {
    blocks(md)
        .into_iter()
        .filter(|b| b.info == DOC_TEST)
        .flat_map(|b| {
            let at = first + b.first - 1;
            b.lines.into_iter().enumerate().filter(|(_, l)| !l.trim().is_empty()).map(move |(i, text)| DocLine { at: format!("{file}:{}", at + i), text }).collect::<Vec<_>>()
        })
        .collect()
}

/// The words of one doc-test line: split on whitespace, single and double
/// quotes honoured, a comment (two spaces or more, then `#`) dropped; `Err`
/// for shell syntax outside quotes ([`META`], or a `#` that starts no
/// comment), for what zsh expands in double quotes, and for an unclosed quote.
fn words(line: &str) -> Result<Vec<String>, String> {
    #[derive(PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let mut out = Vec::new();
    let mut word = String::new();
    let mut open = false;
    let mut quote = Quote::None;
    let mut spaces = 0usize;
    for c in line.chars() {
        match quote {
            Quote::Single if c == '\'' => quote = Quote::None,
            Quote::Single => word.push(c),
            Quote::Double if c == '"' => quote = Quote::None,
            Quote::Double if META_IN_DOUBLE.contains(&c) => return Err(format!("`{c}` inside double quotes (zsh expands it there): single-quote the word")),
            Quote::Double => word.push(c),
            Quote::None if c.is_whitespace() => {
                if open {
                    out.push(std::mem::take(&mut word));
                    open = false;
                }
                spaces += 1;
                continue;
            }
            Quote::None if c == '#' && !open && spaces >= 2 => return Ok(out),
            Quote::None if c == '#' => return Err("`#` outside quotes that starts no comment (a comment is two spaces, then `#`)".into()),
            Quote::None if META.contains(&c) => return Err(format!("`{c}` outside quotes (shell syntax: quote the word, or leave it out)")),
            Quote::None => {
                open = true;
                match c {
                    '\'' => quote = Quote::Single,
                    '"' => quote = Quote::Double,
                    _ => word.push(c),
                }
            }
        }
        spaces = 0;
    }
    if quote != Quote::None {
        return Err("an unclosed quote".into());
    }
    if open {
        out.push(word);
    }
    Ok(out)
}

/// A word that reads as a placeholder: capitals (digits and `_` beside them) only.
fn is_placeholder(word: &str) -> bool {
    word.chars().any(|c| c.is_ascii_uppercase()) && word.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// What a documented command runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Planned {
    /// The arguments after `ai-env`: the placeholders filled in, the dry form applied.
    args: Vec<String>,
    /// Its row of [`DRY_FORMS`]: what the run is judged against.
    form: DryForm,
}

/// The dry form of one doc-test line (the module doc's rules, [`DRY_FORMS`]),
/// its placeholders filled in by `fill`; `Err` says why the line cannot run.
fn plan(line: &str, fill: &dyn Fn(&str) -> Option<String>) -> Result<Planned, String> {
    let words = words(line)?;
    let Some(("ai-env", rest)) = words.split_first().map(|(first, rest)| (first.as_str(), rest)) else {
        return Err("not one `ai-env` command".into());
    };
    if let Some(flag) = rest.iter().find(|w| ACTING_FLAGS.contains(&w.as_str())) {
        return Err(format!("`{flag}` makes it act: a doc-test line is read-only or has a dry form"));
    }
    let filled_word = |word: &str| -> Result<String, String> {
        if !is_placeholder(word) {
            return Ok(word.to_string());
        }
        fill(word).ok_or_else(|| format!("unknown placeholder {word} (the doc-test fills in {})", PLACEHOLDERS.join(", ")))
    };
    let mut args = Vec::with_capacity(rest.len() + 1);
    for word in rest {
        args.push(match word.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => format!("{flag}={}", filled_word(value)?),
            _ => filled_word(word)?,
        });
    }
    let Some(form) = DRY_FORMS.iter().find(|f| rest.len() >= f.cmd.len() && rest.iter().zip(f.cmd).all(|(w, c)| w == c)) else {
        return Err("has no dry form (tests/readme.rs DRY_FORMS lists the commands the docs may run)".into());
    };
    match form.dry {
        Dry::Drop(flag) => args.retain(|a| a != flag),
        Dry::Add(flag) if !args.iter().any(|a| a == flag) => args.push(flag.to_string()),
        Dry::Add(_) | Dry::AsIs => {}
    }
    Ok(Planned { args, form: *form })
}

/// A stderr line the planted world itself causes, which says nothing about
/// the documented command: the lab knobs' banner, the note of the runtime
/// key's unseal that the fake API does not use, and `wrapper install`'s
/// warning that its sibling `ai-env-claude` sits under `target/` (the
/// binaries under test do).
fn worlds_own(line: &str) -> bool {
    line.starts_with("ai-env: LAB KNOBS ACTIVE (")
        || (line.starts_with("ai-env: ") && line.ends_with(" (unsealed; the fake API does not use it)"))
        || (line.starts_with("ai-env: warning: ") && line.contains("/target/") && line.contains(" is under a build directory: "))
}

/// The lines of a fake's log so far (no log yet: no lines).
fn log_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path).unwrap_or_default().lines().map(str::to_string).collect()
}

/// The README and SKILL.md, read from the repository.
fn docs() -> (String, String) {
    let read = |rel: &str| std::fs::read_to_string(Path::new(REPO).join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    (read("README.md"), read("skills/ai-env/SKILL.md"))
}

/// The doc-test lines of the README's S8 section, then of its S9 and S10 sections, then of SKILL.md.
fn documented_lines() -> Vec<DocLine> {
    let (readme, skill) = docs();
    let mut lines = Vec::new();
    for heading in [SECTION, S9_SECTION, S10_SECTION] {
        let (first, text) = section(&readme, heading).unwrap_or_else(|| panic!("README.md has no {heading:?} section"));
        lines.extend(doc_lines(text, "README.md", first));
    }
    lines.extend(doc_lines(&skill, "skills/ai-env/SKILL.md", 1));
    lines
}

// ---- the planted world --------------------------------------------------------------------

/// One request the stand-in endpoint saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    /// Its `x-aws-proxy-port`.
    port: String,
    body: Vec<u8>,
}

/// A stand-in for the MicroVM endpoint on loopback, reached through
/// `AI_ENV_BRIDGE_LAB_AGENT_ADDR`: it records every request and answers
/// `POST /codeout` with the manifest of a VM whose `main` is the fixture's
/// HEAD, without a pack (what `box fetch --dry-run` reads); anything else
/// is 404. Stopped and joined when dropped.
struct Endpoint {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Endpoint {
    fn start(head: &str) -> Endpoint {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the stand-in endpoint");
        let addr = listener.local_addr().expect("its address");
        let manifest = CodeoutManifest {
            v: SeedManifest::V,
            object_format: ObjectFormat::Sha1,
            refs: BTreeMap::from([(format!("refs/heads/{BRANCH}"), head.to_string())]),
            head: head.to_string(),
            branch: Some(BRANCH.to_string()),
            wip_ref: None,
            wip_skipped: None,
        };
        manifest.check().expect("the stand-in's manifest passes the wire's check");
        let line = head_line(&manifest).expect("the manifest's line");
        let (seen, stop) = (Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)));
        let thread = {
            let (seen, stop) = (seen.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(stream, &line, &seen);
                    }
                }
            })
        };
        Endpoint { addr, seen, stop, thread: Some(thread) }
    }

    /// The requests so far.
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accept loop, which sees the flag and ends.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(5));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// One request: its head, its body (by `Content-Length`), recorded; then
/// the answer, `Connection: close`.
fn serve(stream: TcpStream, manifest_line: &[u8], seen: &Mutex<Vec<Seen>>) {
    let _ = stream.set_read_timeout(Some(LIMIT));
    let _ = stream.set_write_timeout(Some(LIMIT));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or_default().to_string(), parts.next().unwrap_or_default().to_string());
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    let mut body = vec![0; len.min(1 << 20)];
    let _ = reader.read_exact(&mut body);
    let port = headers.get("x-aws-proxy-port").cloned().unwrap_or_default();
    let codeout = method == "POST" && path == "/codeout";
    seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Seen { method, path, port, body });
    let mut out = stream;
    let answer = if codeout {
        let mut a = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", manifest_line.len()).into_bytes();
        a.extend_from_slice(manifest_line);
        a
    } else {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    };
    let _ = out.write_all(&answer).and_then(|()| out.flush());
}

/// `cmd` run to its end, its output captured, bounded by [`LIMIT`] (killed and failed past it).
fn bounded(mut cmd: Command) -> Output {
    fn drain(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = r.read_to_end(&mut v);
            v
        })
    }
    let what = format!("{cmd:?}");
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap_or_else(|e| panic!("{what}: {e}"));
    let (out, err) = (drain(child.stdout.take().expect("piped stdout")), drain(child.stderr.take().expect("piped stderr")));
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: still running after {LIMIT:?}, killed");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().expect("stdout reader"), stderr: err.join().expect("stderr reader") }
}

/// The last `n` lines of a command's stdout and stderr.
fn tail(o: &Output, n: usize) -> String {
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let lines: Vec<&str> = all.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// `work` made a git repository on [`BRANCH`] by the real git, with
/// neither the system's nor a global config and fixed dates: one commit
/// (a README, a source file, an ignore rule, and an `image/` with a
/// MANIFEST for `wrapper settings-sync`), then a change of each kind the
/// seed carries or leaves: an edit, a staged file, an untracked file, an
/// ignored file. Its HEAD.
fn fixture_repo(work: &Path) -> String {
    let git = |args: &[&str]| -> Output {
        let o = Command::new(common::git_real())
            .args(args)
            .current_dir(work)
            .env_clear()
            .env("HOME", work.parent().unwrap_or(work))
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "ai-env fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@ai-env.invalid")
            .env("GIT_AUTHOR_DATE", "2026-10-12T08:00:00+00:00")
            .env("GIT_COMMITTER_NAME", "ai-env fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@ai-env.invalid")
            .env("GIT_COMMITTER_DATE", "2026-10-12T08:00:00+00:00")
            .stdin(Stdio::null())
            .output()
            .expect("run the real git");
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        o
    };
    let write = |rel: &str, text: &str| {
        let path = work.join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("{rel}: {e}"));
    };
    git(&["init", "-q", "-b", BRANCH]);
    write("README.md", "fixture\n");
    write("src/lib.rs", "pub fn answer() -> u32 {\n    42\n}\n");
    write(".gitignore", "*.log\n");
    write("image/MANIFEST", "# kind  path                  mode\nfile    claude/settings.json  0644\n");
    write("image/claude/settings.json", "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[]}}\n");
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "fixture"]);
    write("README.md", "fixture\nedited on the Mac\n");
    write("notes.md", "staged on the Mac\n");
    git(&["add", "notes.md"]);
    write("todo.txt", "untracked on the Mac\n");
    write("debug.log", "ignored on the Mac\n");
    String::from_utf8_lossy(&git(&["rev-parse", "HEAD"]).stdout).trim().to_string()
}

/// `tests/fakes/logged.sh` under every name of [`REFUSED_TOOLS`] in `bin`,
/// one inode for all (macOS assesses a new executable's first exec once).
fn install_refusers(root: &Path, bin: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let master = root.join("refuse");
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/logged.sh"), &master).expect("copy logged.sh");
    std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    for name in REFUSED_TOOLS {
        let dest = bin.join(name);
        if std::fs::hard_link(&master, &dest).is_err() {
            std::fs::copy(&master, &dest).expect("copy the refuser");
        }
    }
}

/// What the comparison keeps of a file at `rel`: its bytes' sha256, but
/// for what a read rewrites without changing anything. A lock's file holds
/// its last holder's pid (`vm::lock`): only that it exists counts. A VM's
/// row records the expiry of each token minted for the VM
/// (`vm::token::mint`; `box fetch --dry-run` mints one to read the VM's
/// refs): the row is compared without `token_expiries`.
fn content(rel: &str, bytes: &[u8]) -> String {
    use sha2::Digest;
    if rel.ends_with(".lock") {
        return "a lock".into();
    }
    if rel.starts_with("bridge/state/vms/") && rel.ends_with(".toml") {
        if let Some(mut row) = std::str::from_utf8(bytes).ok().and_then(|t| t.parse::<toml::Value>().ok()) {
            if let Some(t) = row.as_table_mut() {
                t.remove("token_expiries");
            }
            return format!("a VM row {}", hex::encode(sha2::Sha256::digest(row.to_string().as_bytes())));
        }
    }
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Every entry under `dir` by its path relative to it: a directory and its
/// mode, a file's mode and [`content`], a link's target. `skip` leaves a
/// relative path (and what is under it) out.
fn tree(dir: &Path, skip: &dyn Fn(&str) -> bool) -> BTreeMap<String, String> {
    fn walk(base: &Path, dir: &Path, skip: &dyn Fn(&str) -> bool, out: &mut BTreeMap<String, String>) {
        use std::os::unix::fs::PermissionsExt;
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let rel = path.strip_prefix(base).expect("under the base").to_string_lossy().into_owned();
            if skip(&rel) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            let mode = meta.permissions().mode() & 0o7777;
            let what = if meta.file_type().is_symlink() {
                format!("link {}", std::fs::read_link(&path).map(|t| t.display().to_string()).unwrap_or_default())
            } else if meta.is_dir() {
                walk(base, &path, skip, out);
                format!("dir {mode:o}")
            } else if meta.is_file() {
                format!("file {mode:o} {}", content(&rel, &std::fs::read(&path).unwrap_or_default()))
            } else {
                "other".to_string()
            };
            out.insert(rel, what);
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, skip, &mut out);
    out
}

/// What a dry form may leave in the HOME tree: anything under the bridge's
/// `logs/`; the seed's clean-object cache (`state/scan-cache/`, the ids of
/// objects a scan found clean, no content); the parent of its scratch
/// repositories (`state/tmp`, which must end empty); and the settings diff
/// `session show --settings-diff` writes beside the captures (plan §9); and
/// the local reconcile's stamp and lock (`state/gc.stamp`, `state/gc.lock`;
/// S10 L12).
fn allowed_change(rel: &str) -> bool {
    let under = |dir: &str| rel == dir || rel.starts_with(&format!("{dir}/"));
    under("bridge/logs") || under("bridge/state/scan-cache") || rel == "bridge/state/tmp" || (rel.starts_with("bridge/quarantine/") && rel.ends_with("/settings/diff.json")) || rel == "bridge/state/gc.stamp" || rel == "bridge/state/gc.lock"
}

/// What a command did to the audit log, `before` and `after` its run, that
/// its row does not allow: the log must only grow, by whole JSON rows whose
/// `event` is one of `allowed` (none for most rows). Each problem in a line.
fn audit_problems(allowed: &[&str], before: &[u8], after: &[u8]) -> Vec<String> {
    let Some(added) = after.strip_prefix(before) else {
        return vec!["rewrote the audit log (a row before its run changed or went)".to_string()];
    };
    if !added.is_empty() && !added.ends_with(b"\n") {
        return vec!["left a torn row at the end of the audit log".to_string()];
    }
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(added).lines() {
        match serde_json::from_str::<Value>(line).ok().and_then(|v| v["event"].as_str().map(str::to_string)) {
            Some(event) if allowed.contains(&event.as_str()) => {}
            Some(event) => out.push(format!("appended the audit row {event} (the row allows {allowed:?})")),
            None => out.push(format!("appended an audit line that is no row: {line}")),
        }
    }
    out
}

/// What differs between two trees: each path whose entry was added,
/// removed or changed, and what it was and became.
fn changes(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut paths: Vec<&String> = before.keys().chain(after.keys()).collect();
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .filter(|p| before.get(*p) != after.get(*p))
        .map(|p| (p.clone(), format!("{} -> {}", before.get(p).map_or("absent", String::as_str), after.get(p).map_or("absent", String::as_str))))
        .collect()
}

/// The planted world (the module doc): `<root>/home` is `HOME` and S7's
/// green world (`bridge/`, `keys/`, and `bin/` with the fakes, first on
/// `PATH`); `<root>/repo` the workspace; `<root>/fake.json` the fake API;
/// the fakes' logs beside them, outside HOME.
struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
    head: String,
    vm: String,
    session: String,
    endpoint: Endpoint,
}

impl World {
    fn new() -> World {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonical tempdir");
        let (home, repo) = (root.join("home"), root.join("repo"));
        for dir in [home.join("bin"), repo.clone(), root.join("tmp")] {
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
        }
        let head = fixture_repo(&repo);
        let fake = root.join("fake.json");
        std::fs::write(&fake, serde_json::to_string_pretty(&FakeState { auto_advance: true, ..FakeState::new() }).expect("the fake's state")).expect("write fake.json");
        install_refusers(&root, &home.join("bin"));
        common::install_fake_git(&home.join("bin").join("git"), &root.join("git.log"), &[]);
        let endpoint = Endpoint::start(&head);
        let mut w = World { _tmp: tmp, root, home, repo, head, vm: String::new(), session: common::uuid(0x5e55), endpoint };
        let roots = [w.repo.clone()];
        let token = green_world::setup_token("Dt");
        green_world::Green { root: &w.home, fake: &fake, roots: &roots }.seed(&token, IMAGE_VERSION, true, &|args| {
            let mut cmd = w.ai_env(args, &w.root.join("age-setup.log"));
            cmd.env("AI_ENV_PASTE_STDIN", "1");
            cmd
        });
        // An S9 image's VM: its `/health` names the workspace routes' capability, git smart-HTTP's and the
        // transcript store's, which `vm health` records (once the S3 cut-over holds, SELECT_VM reuses no VM
        // without `transcript_s3_v1`, and `vm warm --dry-run` reuses this one).
        FileFakeMicrovmApi::open(&fake)
            .and_then(|api| {
                api.with(|s| {
                    s.health_caps.extend([CAP_WORKSPACE_V1, CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1].map(str::to_string));
                    Ok(())
                })
            })
            .expect("the fake's caps");
        let work = w.repo.display().to_string();
        let run = w.setup(&["vm", "run", "--egress", "vpc", "--workspace", &work, "--json"]);
        let v: Value = serde_json::from_slice(&run.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", String::from_utf8_lossy(&run.stdout)));
        w.vm = v["id"].as_str().unwrap_or_else(|| panic!("no id in {v}")).to_string();
        let vm = w.vm.clone();
        w.setup(&["vm", "health", &vm]);
        w.plant_session();
        w
    }

    /// `ai-env args` in the world's environment (no other variable of this
    /// process), in the workspace, stdin `/dev/null`, the fake age logging to `age_log`.
    fn ai_env(&self, args: &[&str], age_log: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        cmd.args(args)
            .current_dir(&self.repo)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", format!("{}:/usr/bin:/bin", self.home.join("bin").display()))
            .env("TMPDIR", self.root.join("tmp"))
            .env("AI_ENV_BRIDGE_DIR", self.home.join("bridge"))
            .env("AI_ENV_DIR", self.home.join("keys"))
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AI_ENV_BRIDGE_LAB_FAKE_API", self.root.join("fake.json"))
            .env("AI_ENV_BRIDGE_LAB_AGENT_ADDR", self.endpoint.addr.to_string())
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "100")
            .env("FAKE_AGE_LOG", age_log)
            .env("FAKE_LOG", self.tools_log())
            .stdin(Stdio::null());
        cmd
    }

    /// A setup command, which must succeed.
    fn setup(&self, args: &[&str]) -> Output {
        let o = bounded(self.ai_env(args, &self.root.join("age-setup.log")));
        assert!(o.status.success(), "setup: ai-env {}: {}", args.join(" "), tail(&o, 20));
        o
    }

    /// The fake age's log of the documented commands.
    fn age_log(&self) -> PathBuf {
        self.root.join("age.log")
    }

    /// The refused tools' log (`tests/fakes/logged.sh`), setup included.
    fn tools_log(&self) -> PathBuf {
        self.root.join("tools.log")
    }

    /// A documented command's run. It unseals the runtime key as against AWS
    /// (`AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL`): each Touch ID it would cost is a
    /// decrypt in the fake age's log.
    fn run(&self, args: &[String]) -> Output {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut cmd = self.ai_env(&args, &self.age_log());
        cmd.env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1");
        bounded(cmd)
    }

    /// A placeholder's value.
    fn fill(&self, name: &str) -> Option<String> {
        match name {
            "WORKSPACE" => Some(self.repo.display().to_string()),
            "UUID" => Some(self.session.clone()),
            "ID" => Some(self.vm.clone()),
            "BRANCH" => Some(BRANCH.to_string()),
            _ => None,
        }
    }

    /// The world's bridge root (`AI_ENV_BRIDGE_DIR`).
    fn bridge(&self) -> Paths {
        Paths::from_root_and_env(self.home.join("bridge"), None)
    }

    /// A closed remote chat of the workspace on the VM, as the wrapper
    /// registers one, and its two settings captures (a rule approved in
    /// the VM between them), as W8's capture writes them.
    fn plant_session(&self) {
        let paths = self.bridge();
        let slug = ai_env_cli::wire::slug::project_dir_name(&self.repo).expect("the workspace's slug");
        let row = SessionRow {
            v: registry::REGISTRY_SCHEMA_V,
            session_id: self.session.clone(),
            slug: Some(slug.clone()),
            cwd: Some(self.repo.display().to_string()),
            transcript_rel: Some(format!("{slug}/{}.jsonl", self.session)),
            created: registry::now_rfc3339(),
            last_seen: registry::now_rfc3339(),
            status: "closed".into(),
            mode: "remote".into(),
            route: "remote".into(),
            exit: Some(0),
            microvm_id: Some(self.vm.clone()),
            seeded_head: Some(self.head.clone()),
            ..SessionRow::default()
        };
        registry::write(&paths, &row).expect("plant the session's row");
        let vm_cwd = ai_env_cli::wire::workspace::vm_path_of(&self.repo).expect("the workspace's VM path");
        for (phase, allow) in [(CapturePhase::Start, "[]"), (CapturePhase::Turn, "[\"Bash(git status)\"]")] {
            use sha2::Digest;
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            let text = format!("{{\"permissions\":{{\"allow\":{allow}}}}}\n");
            let absent = |scope, path: String| SettingsFile { scope, path, present: false, size: 0, sha256: None, text: None, skipped: None };
            let capture = SettingsCapture {
                path: vm_cwd.clone(),
                files: vec![
                    absent(SettingsScope::User, "/Users/mike/.claude/settings.json".into()),
                    absent(SettingsScope::Project, format!("{vm_cwd}/.claude/settings.json")),
                    SettingsFile {
                        scope: SettingsScope::Local,
                        path: format!("{vm_cwd}/.claude/settings.local.json"),
                        present: true,
                        size: text.len() as u64,
                        sha256: Some(hex::encode(sha2::Sha256::digest(text.as_bytes()))),
                        text: Some(text.clone()),
                        skipped: None,
                    },
                ],
                project: BTreeMap::new(),
                at: registry::now_rfc3339(),
            };
            capture.check().expect("a capture the wire takes");
            let path = capture_path(&paths, &self.session, phase).expect("the capture's path");
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path.parent().expect("its directory")).expect("mkdir the quarantine");
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).expect("create the capture");
            file.write_all(serde_json::to_string_pretty(&capture).expect("the capture's JSON").as_bytes()).expect("write the capture");
        }
    }

    /// The fake API's state.
    fn fake(&self) -> FakeState {
        FileFakeMicrovmApi::open(&self.root.join("fake.json")).and_then(|api| api.snapshot()).expect("the fake's state")
    }

    /// The HOME tree (the module doc).
    fn home_tree(&self) -> BTreeMap<String, String> {
        tree(&self.home, &|_| false)
    }

    /// The fixture repository as the doc-test compares it: its refs, HEAD,
    /// status (untracked and ignored files included), index entries and
    /// stash, read by the real git without taking a lock; and every file of
    /// it but `.git/index` (which a status may refresh), byte for byte.
    fn repo_state(&self) -> BTreeMap<String, String> {
        let git = |args: &[&str]| -> String {
            let o = Command::new(common::git_real())
                .args(args)
                .current_dir(&self.repo)
                .env_clear()
                .env("HOME", &self.root)
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_OPTIONAL_LOCKS", "0")
                .stdin(Stdio::null())
                .output()
                .expect("run the real git");
            format!("{} {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout))
        };
        let mut state = tree(&self.repo, &|rel| rel == ".git/index");
        for (key, args) in [
            ("git: refs", &["for-each-ref", "--format=%(refname) %(objectname)"][..]),
            ("git: HEAD", &["symbolic-ref", "-q", "HEAD"]),
            ("git: HEAD id", &["rev-parse", "HEAD"]),
            ("git: status", &["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored"]),
            ("git: index", &["ls-files", "-s", "-z"]),
            ("git: stash", &["stash", "list"]),
        ] {
            state.insert(key.to_string(), git(args));
        }
        state
    }
}

// ---- the tests ----------------------------------------------------------------------------

/// The doc-test itself (the module doc): every `sh doc-test` line of the
/// README's S8, S9 and S10 sections and of SKILL.md runs in its dry form in the
/// planted world, asks for what its row allows and no more, and changes
/// nothing a dry run may not change. Every failure is listed, each laid at
/// the door of the line that caused it, the world's checks too, before the
/// test fails.
#[test]
fn readme_doc_test_blocks_run_in_their_dry_forms() {
    let lines = documented_lines();
    let w = World::new();
    let repo_before = w.repo_state();
    let mut problems = Vec::new();
    // HOME before each command, so a change is laid at the door of the command that made it.
    let mut home = w.home_tree();
    let audit_log = w.home.join(AUDIT_LOG);
    for line in &lines {
        let planned = match plan(&line.text, &|name| w.fill(name)) {
            Ok(p) => p,
            Err(why) => {
                problems.push(format!("{}: `{}`: {why}", line.at, line.text));
                continue;
            }
        };
        let (form, ran) = (planned.form, format!("ai-env {}", planned.args.join(" ")));
        let (calls_at, age_at, tools_at) = (w.fake().calls.len(), log_lines(&w.age_log()).len(), log_lines(&w.tools_log()).len());
        let audit_at = std::fs::read(&audit_log).unwrap_or_default();
        let out = w.run(&planned.args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let code = out.status.code();
        let says = form.says.is_empty() || form.says.iter().any(|s| stdout.contains(s));
        if !code.is_some_and(|c| form.codes.contains(&c)) || !says {
            let expect = if says { format!("an exit in {:?}", form.codes) } else { format!("stdout naming one of {:?}", form.says) };
            problems.push(format!("{}: `{}` ran as `{ran}`: exit {code:?}, expected {expect}\n{}", line.at, line.text, tail(&out, 12)));
        }
        // No warning; after exit 0 no `ai-env:` line at all but the world's own (an error line comes with its exit).
        for said in String::from_utf8_lossy(&out.stderr).lines().filter(|l| !worlds_own(l)) {
            if said.starts_with("ai-env: warning:") || said.starts_with("warning:") || (code == Some(0) && said.starts_with("ai-env:")) {
                problems.push(format!("{}: `{ran}` said on stderr: {said}", line.at));
            }
        }
        // The control plane: only the calls its row allows.
        let calls = w.fake().calls;
        for call in calls.iter().skip(calls_at).filter(|c| !form.api.allows(c)) {
            problems.push(format!("{}: `{ran}`: the fake API recorded {call:?} (the row allows {:?})", line.at, form.api));
        }
        // Its Touch IDs, exactly: the fake age's decrypts; nothing sealed, nothing else run but version probes.
        let age: Vec<String> = log_lines(&w.age_log()).into_iter().skip(age_at).collect();
        let decrypts = age.iter().filter(|l| l.starts_with("age -d ")).count();
        if decrypts != usize::from(form.unseals) {
            problems.push(format!("{}: `{ran}` asked for {decrypts} Touch ID(s), the fake age's decrypts (the row says {})", line.at, form.unseals));
        }
        for other in age.iter().filter(|l| !l.starts_with("age -d ") && !l.ends_with(" --version")) {
            problems.push(format!("{}: `{ran}`: the fake age ran `{other}`: neither an unseal nor a version probe", line.at));
        }
        // The refused tools: the doctor's probes only.
        if !form.tools {
            for tool in log_lines(&w.tools_log()).iter().skip(tools_at) {
                problems.push(format!("{}: `{ran}` ran the refused `{tool}` (only the doctor probes the tools)", line.at));
            }
        }
        // The audit log: appended to only by the rows its row names (judged here, so the tree skips it).
        for why in audit_problems(form.audits, &audit_at, &std::fs::read(&audit_log).unwrap_or_default()) {
            problems.push(format!("{}: `{ran}` {why}", line.at));
        }
        let after = w.home_tree();
        for (path, change) in changes(&home, &after).into_iter().filter(|(path, _)| !allowed_change(path) && path != AUDIT_LOG) {
            problems.push(format!("{}: `{ran}` changed HOME: {path}: {change}", line.at));
        }
        home = after;
    }
    // The data plane only read: a code-out's manifest, asked without a snapshot.
    let seen = w.endpoint.seen();
    for s in &seen {
        let body: Value = serde_json::from_slice(&s.body).unwrap_or(Value::Null);
        if (s.method.as_str(), s.path.as_str(), s.port.as_str()) != ("POST", "/codeout", "9418") || body["wip"] != Value::Bool(false) {
            problems.push(format!("the endpoint saw {} {} (port {:?}, body {body}): not a code-out read", s.method, s.path, s.port));
        }
    }
    if !seen.iter().any(|s| s.path == "/codeout") {
        problems.push("no documented command read the VM's refs (`box fetch --dry-run` never reached the endpoint)".into());
    }
    // HOME: nothing changed after the last command either; no scratch left behind.
    let home_after = w.home_tree();
    for (path, change) in changes(&home, &home_after).into_iter().filter(|(path, _)| !allowed_change(path)) {
        problems.push(format!("HOME changed after the last command: {path}: {change}"));
    }
    for left in home_after.keys().filter(|p| p.starts_with("bridge/state/tmp/")) {
        problems.push(format!("a scratch entry was left behind: {left}"));
    }
    // The workspace: refs, index, status, stash and files as they were.
    for (path, change) in changes(&repo_before, &w.repo_state()) {
        problems.push(format!("the fixture repository changed: {path}: {change}"));
    }
    assert!(problems.is_empty(), "{} problem(s) in the doc-test of {} documented commands:\n\n{}", problems.len(), lines.len(), problems.join("\n\n"));
}

/// Both S8 sections and the README's S9 and S10 sections exist and doc-test
/// their commands: each holds `sh doc-test` lines, and no plain `sh` block
/// there holds an `ai-env` command, which would escape the doc-test (git and
/// make commands sit in plain blocks; the commands without a dry form, such
/// as S9's `session stage` and S10's `session migrate`, are named in the
/// prose).
#[test]
fn the_s8_sections_doc_test_every_ai_env_command() {
    let (readme, skill) = docs();
    let mut escaped = Vec::new();
    for (file, md, heading, at_least) in [("README.md", &readme, SECTION, 12), ("README.md", &readme, S9_SECTION, 4), ("README.md", &readme, S10_SECTION, 4), ("skills/ai-env/SKILL.md", &skill, SKILL_SECTION, 5)] {
        let (first, text) = section(md, heading).unwrap_or_else(|| panic!("{file} has no {heading:?} section"));
        let n = doc_lines(text, file, first).len();
        assert!(n >= at_least, "{file}'s {heading:?} holds {n} doc-test lines (at least {at_least})");
        for b in blocks(text).into_iter().filter(|b| b.info.split_whitespace().next() == Some("sh") && b.info != DOC_TEST) {
            for (i, l) in b.lines.iter().enumerate().filter(|(_, l)| l.split_whitespace().next() == Some("ai-env")) {
                escaped.push(format!("{file}:{}: `{l}`", first + b.first - 1 + i));
            }
        }
    }
    assert!(escaped.is_empty(), "ai-env commands in plain sh blocks, which the doc-test never runs (put them in `sh doc-test` blocks):\n{}", escaped.join("\n"));
}

/// Every `ai-env CMD [SUB]` of the README's Commands block, each `|`
/// alternative's subcommand included, answers `--help` with exit 0. The
/// `shim` line needs the shim feature: without it (the bridge-only world)
/// the command must not exist.
#[test]
fn readme_commands_block_parses() {
    #[cfg(feature = "shim")]
    const WITH_SHIM: bool = true;
    #[cfg(not(feature = "shim"))]
    const WITH_SHIM: bool = false;
    let (readme, _) = docs();
    let (first, text) = section(&readme, "## Commands").expect("README.md has a Commands section");
    let block = blocks(text).into_iter().next().expect("the Commands block");
    let sub = |w: Option<&str>| w.filter(|w| w.starts_with(|c: char| c.is_ascii_lowercase()) && w.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')).map(str::to_string);
    let mut asked: Vec<(usize, Vec<String>, bool)> = Vec::new();
    for (i, line) in block.lines.iter().enumerate() {
        let command = line.split(" #").next().unwrap_or_default();
        let mut words = command.split_whitespace();
        if words.next() != Some("ai-env") {
            continue;
        }
        let Some(cmd) = words.next().map(str::to_string) else { continue };
        let shim = cmd == "shim";
        let at = first + block.first - 1 + i;
        let mut alternatives = command.split(" | ");
        let head = alternatives.next().unwrap_or_default();
        asked.push((at, [Some(cmd.clone()), sub(head.split_whitespace().nth(2))].into_iter().flatten().collect(), shim));
        for alt in alternatives {
            if let Some(s) = sub(alt.split_whitespace().next()) {
                asked.push((at, vec![cmd.clone(), s], shim));
            }
        }
    }
    let mut once = std::collections::BTreeSet::new();
    asked.retain(|(_, args, _)| once.insert(args.clone()));
    assert!(asked.len() >= 40, "only {} commands found in the Commands block", asked.len());
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut failures = Vec::new();
    for (at, args, shim) in &asked {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        cmd.args(args).arg("--help").env_clear().env("HOME", tmp.path()).env("PATH", "/usr/bin:/bin").stdin(Stdio::null());
        let out = bounded(cmd);
        let ok = if *shim && !WITH_SHIM { out.status.code() == Some(2) } else { out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Usage:") };
        if !ok {
            failures.push(format!("README.md:{at}: `ai-env {} --help`: exit {:?}\n{}", args.join(" "), out.status.code(), tail(&out, 6)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// The README shows the VM's CLAUDE.md as the image bakes it, byte for byte,
/// once, in the S8 section.
#[test]
fn readme_vm_claude_md_snippet_is_the_image_file() {
    let (readme, _) = docs();
    let image = std::fs::read_to_string(Path::new(REPO).join("image/claude/CLAUDE.md")).expect("image/claude/CLAUDE.md");
    let copies: Vec<Block> = blocks(&readme).into_iter().filter(|b| b.info == VM_CLAUDE_MD).collect();
    assert_eq!(copies.len(), 1, "one ```{VM_CLAUDE_MD} block in README.md");
    assert_eq!(copies[0].text(), image, "README.md's copy (line {}) differs from image/claude/CLAUDE.md", copies[0].first);
    let (_, s8) = section(&readme, SECTION).expect("the S8 section");
    assert_eq!(blocks(s8).iter().filter(|b| b.info == VM_CLAUDE_MD).count(), 1, "the copy sits in the S8 section");
}

/// Every JSON block of the README and SKILL.md parses (the kill switch's among them).
#[test]
fn readme_json_blocks_parse() {
    let (readme, skill) = docs();
    let mut n = 0;
    for (file, md) in [("README.md", &readme), ("skills/ai-env/SKILL.md", &skill)] {
        for b in blocks(md).into_iter().filter(|b| b.info.split_whitespace().next() == Some("json")) {
            n += 1;
            if let Err(e) = serde_json::from_str::<Value>(&b.text()) {
                panic!("{file}:{}: a json block that does not parse: {e}", b.first);
            }
        }
    }
    let (_, s8) = section(&readme, SECTION).expect("the S8 section");
    let kill: Vec<Value> = blocks(s8).iter().filter(|b| b.info == "json").filter_map(|b| serde_json::from_str(&b.text()).ok()).collect();
    assert!(kill.iter().any(|v| v["claudeCode.environmentVariables"][0] == serde_json::json!({ "name": "AI_ENV_BRIDGE_LOCAL", "value": "1" })), "the S8 section shows the kill switch as Cursor's settings hold it");
    assert!(n >= 1, "no json block at all");
}

/// `text`'s words joined by one space: a quote the README wraps over lines
/// reads as the one line the wrapper writes.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Why a stayed note says the chat stayed after an unanswered Touch ID, as
/// the README quotes it. The pump's `stayed_why` words it, a private
/// function, so this text is the test's own: the one part of the quotes
/// below that is not taken from the code.
const STAYED_UNANSWERED: &str = "no Touch ID in time";

/// The README's S10 section quotes what the wrapper writes as the code
/// writes it (whitespace aside: a quote may wrap), the VM named `ID`: the
/// notes a move, a restart and a migration leave in the chat
/// (`remote::note_*`; the stayed note's reason is [`STAYED_UNANSWERED`]),
/// the words of the other causes and of the wall's end (each quoted on its
/// own), and the lines Cursor shows for a chat past its moves, for a failed
/// move (the failure's own line in its middle shown as `…`) and for
/// `[vm].max_concurrent` naming a parked VM. A text the code changes fails
/// here before the docs drift from it.
#[test]
fn the_s10_section_quotes_the_wrappers_notes_and_lines() {
    let (readme, _) = docs();
    let (_, s10) = section(&readme, S10_SECTION).unwrap_or_else(|| panic!("README.md has no {S10_SECTION:?} section"));
    let text = flat(s10);
    let vm = "ID";
    let inner = Failure::TouchIdCancelled;
    let failed = Failure::Move { kind: MoveKind::Readdress, from_vm: vm.into(), cause: Some(LossCause::VmGone), inner: Box::new(inner.clone()) }.line();
    assert!(failed.contains(&inner.line()), "the failure's own line, whole: {failed}");
    let quotes = [
        remote::note_moving(vm, LossCause::VmGone),
        remote::note_move_at_next(vm, LossCause::VmGone),
        remote::note_continues(vm),
        remote::note_restarting(vm, LossCause::SpawnGone),
        remote::note_restart_at_next(vm, LossCause::SpawnGone),
        remote::note_migrating(vm, &MigrateTrigger::Wall { left_s: 1200 }),
        remote::note_stayed(vm, STAYED_UNANSWERED, StayedThen::Retry),
        Failure::MovesExhausted { vm: vm.into(), moves: VmCfg::default().max_readdress }.line(),
        failed.replace(&inner.line(), "…"),
        Failure::MaxConcurrent { running: VmCfg::default().max_concurrent, parked: vec![vm.into()] }.line(),
    ];
    let mut missing: Vec<String> = quotes.iter().filter(|q| !text.contains(&format!("`{}`", flat(q)))).cloned().collect();
    // Quoted as words of their own: what a note says inside its parentheses for the other causes, and the end of a stayed
    // note once no wall migration is left.
    let inside = |note: &str| note.split_once(" (").and_then(|(_, rest)| rest.split_once(')')).map(|(cause, _)| cause.to_string()).unwrap_or_default();
    let stayed = remote::note_stayed(vm, "WHY", StayedThen::AtWall);
    let words = [inside(&remote::note_moving(vm, LossCause::Unreachable)), inside(&remote::note_restarting(vm, LossCause::Gap)), stayed.rsplit_once("; ").map(|(_, end)| end.to_string()).unwrap_or_default()];
    missing.extend(words.into_iter().filter(|w| w.is_empty() || !text.contains(&format!("`{w}`"))));
    assert!(missing.is_empty(), "README.md's S10 section does not quote these as the wrapper writes them:\n{}", missing.join("\n"));
}

/// The README's S10 section shows `[vm]`'s S10 keys as bridge.toml holds
/// them: its one `toml` block parses as a bridge.toml, passes
/// `VmCfg::validate`, and reads as `VmCfg::default()` (each key it sets is
/// at its default); it names every S10 key, the commented `park_after_s`
/// too, whose value, uncommented, parks after what the default's unset key
/// does (`max_idle_s`).
#[test]
fn the_s10_sections_vm_keys_are_bridge_toml_at_their_defaults() {
    let (readme, _) = docs();
    let (first, s10) = section(&readme, S10_SECTION).unwrap_or_else(|| panic!("README.md has no {S10_SECTION:?} section"));
    let found: Vec<Block> = blocks(s10).into_iter().filter(|b| b.info == "toml").collect();
    assert_eq!(found.len(), 1, "one ```toml block in the S10 section");
    let (block, at) = (&found[0], first + found[0].first - 1);
    let parsed = |text: &str| BridgeConfig::parse(text).unwrap_or_else(|e| panic!("README.md:{at}: the [vm] block: {e}"));
    let cfg = parsed(&block.text());
    cfg.vm.validate().unwrap_or_else(|e| panic!("README.md:{at}: {e}"));
    assert_eq!(cfg.vm, VmCfg::default(), "README.md:{at}: the [vm] block's values are the defaults it says they are");
    let doc: toml::Table = block.text().parse().unwrap_or_else(|e| panic!("README.md:{at}: {e}"));
    let set: Vec<&str> = doc.get("vm").and_then(toml::Value::as_table).map(|t| t.keys().map(String::as_str).collect()).unwrap_or_default();
    for key in ["max_readdress", "park", "migrate_before_wall_s"] {
        assert!(set.contains(&key), "README.md:{at}: the [vm] block sets {key} (it sets {set:?})");
    }
    let uncommented: String = block
        .lines
        .iter()
        .map(|l| match l.strip_prefix("# ") {
            Some(key) if key.starts_with("park_after_s =") => format!("{key}\n"),
            _ => format!("{l}\n"),
        })
        .collect();
    assert_ne!(uncommented, block.text(), "README.md:{at}: the [vm] block names park_after_s, commented out");
    let set_after = parsed(&uncommented).vm;
    set_after.validate().unwrap_or_else(|e| panic!("README.md:{at}: park_after_s uncommented: {e}"));
    assert!(set_after.park_after_s.is_some() && set_after.park_after() == VmCfg::default().park_after(), "README.md:{at}: park_after_s's shown value is what the unset key means ([vm].max_idle_s)");
}

/// The engine on a synthetic page: the dry forms of the table, comments and
/// quotes, and a refusal, naming why, for a command without a dry form, a
/// flag that acts, shell syntax, an unknown placeholder, an unclosed quote,
/// what zsh expands in double quotes, and a line that is no `ai-env` command.
#[test]
fn doc_test_refuses_a_command_without_a_dry_form() {
    let page = "\
# A page

```sh doc-test
ai-env vm terminate ID --yes
ai-env wrapper install --write --mode remote   # fine
ai-env box seed WORKSPACE  # fine too
ai-env box seed WORKSPACE --dry-run
ai-env vm gc --yes
ai-env creds forget --yes
ai-env wrapper settings-sync UUID --rule 'Bash(git status)' --write
ai-env doctor
ai-env creds status --unseal
ai-env wrapper census --record-probes
ai-env vm list | head
ai-env box fetch WORKSPACE > out.txt
ai-env box seed SOMEWHERE
ai-env box seed R
ai-env session show 'UUID
ai-env vm warm \"$HOME\"
ai-env vm warm ~/work
ai-env box seed WORKSPACE #no-space
echo hi
  # a comment alone
```

```sh
ai-env vm terminate ID --yes
```
";
    let fill = |name: &str| match name {
        "WORKSPACE" => Some("/w".to_string()),
        "UUID" => Some("u-1".to_string()),
        "ID" => Some("microvm-1".to_string()),
        _ => None,
    };
    let lines = doc_lines(page, "page.md", 1);
    assert_eq!(lines.len(), 20, "only the doc-test block's lines: {lines:?}");
    assert_eq!(lines[0].at, "page.md:4");
    let plans: Vec<Result<Planned, String>> = lines.iter().map(|l| plan(&l.text, &fill)).collect();
    let args = |i: usize| plans[i].as_ref().unwrap_or_else(|e| panic!("line {i}: {e}")).args.join(" ");
    let why = |i: usize| plans[i].clone().expect_err("refused");
    assert!(why(0).contains("has no dry form"), "{}", why(0));
    assert_eq!(args(1), "wrapper install --mode remote");
    assert_eq!(plans[1].as_ref().map(|p| p.form.says).ok(), Some(&["dry run"][..]));
    assert_eq!(args(2), "box seed /w --dry-run");
    assert_eq!(args(3), "box seed /w --dry-run", "never added twice");
    assert_eq!(args(4), "vm gc");
    assert_eq!(args(5), "creds forget");
    assert_eq!(args(6), "wrapper settings-sync u-1 --rule Bash(git status)", "a quoted word is one word");
    assert_eq!((args(7), plans[7].as_ref().map(|p| p.form.codes).ok()), ("doctor".to_string(), Some(&[0, 1][..])));
    assert!(why(8).contains("`--unseal` makes it act"), "{}", why(8));
    assert!(why(9).contains("`--record-probes` makes it act"), "{}", why(9));
    assert!(why(10).contains("`|` outside quotes"), "{}", why(10));
    assert!(why(11).contains("`>` outside quotes"), "{}", why(11));
    assert!(why(12).contains("unknown placeholder SOMEWHERE"), "{}", why(12));
    assert!(why(13).contains("unknown placeholder R"), "{}", why(13));
    assert!(why(14).contains("an unclosed quote"), "{}", why(14));
    assert!(why(15).contains("inside double quotes"), "{}", why(15));
    assert!(why(16).contains("`~` outside quotes"), "{}", why(16));
    assert!(why(17).contains("`#` outside quotes"), "{}", why(17));
    assert!(why(18).contains("not one `ai-env` command"), "{}", why(18));
    assert!(why(19).contains("not one `ai-env` command"), "{}", why(19));
    // Every character of shell syntax, each on its own: its own list, so one dropped from META or META_IN_DOUBLE fails.
    for c in "$`|;&><*?[](){}~!\\".chars() {
        let why = plan(&format!("ai-env doctor x{c}y"), &fill).expect_err("refused");
        assert!(why.contains(&format!("`{c}` outside quotes")), "{c}: {why}");
    }
    for c in "$`\\!".chars() {
        let why = plan(&format!("ai-env doctor \"x{c}y\""), &fill).expect_err("refused");
        assert!(why.contains(&format!("`{c}` inside double quotes")), "{c}: {why}");
    }
    // S9's rows: the review as written (its audit row allowed), the hook's dry run, the two lists without --yes;
    // the store's commands that act have no dry form.
    let s9 = |line: &str| plan(line, &fill).map(|p| (p.args.join(" "), p.form.audits)).unwrap_or_else(|e| panic!("{line}: {e}"));
    assert_eq!(s9("ai-env box review main  # a comment"), ("box review main".to_string(), &["box_review"][..]));
    assert_eq!(s9("ai-env box hook-install WORKSPACE"), ("box hook-install /w --dry-run".to_string(), &[][..]));
    assert_eq!(s9("ai-env session gc --remote --yes"), ("session gc --remote".to_string(), &[][..]));
    assert_eq!(s9("ai-env session migrate-s9 --yes"), ("session migrate-s9".to_string(), &[][..]));
    // S10's: `session migrate` moves the chat (offline it unseals and starts a VM), and `forget` of several ids acts as one.
    for acting in ["ai-env session stage UUID --warm", "ai-env session sync UUID", "ai-env session forget UUID --purge", "ai-env session forget UUID UUID --purge", "ai-env session migrate UUID", "ai-env session migrate UUID --json"] {
        let why = plan(acting, &fill).expect_err("no dry form");
        assert!(why.contains("has no dry form"), "{acting}: {why}");
    }
    // The audit log: only appended to, by whole rows whose event the row allows.
    let row = |event: &str| format!("{{\"v\":1,\"ts\":\"2026-10-18T08:00:00Z\",\"event\":\"{event}\",\"session_id\":null,\"pid\":1,\"detail\":{{}}}}\n");
    let before = row("vm_run");
    let grown = format!("{before}{}", row("box_review"));
    assert!(audit_problems(&[], before.as_bytes(), before.as_bytes()).is_empty(), "nothing appended");
    assert!(audit_problems(&["box_review"], before.as_bytes(), grown.as_bytes()).is_empty(), "an allowed row");
    for (allowed, after, says) in [
        (&[][..], grown.clone(), "appended the audit row box_review"),
        (&["box_review"][..], row("box_review"), "rewrote the audit log"),
        (&["box_review"][..], format!("{before}not a row\n"), "an audit line that is no row"),
        (&["box_review"][..], format!("{before}{{\"event\":\"box_review\""), "a torn row"),
    ] {
        let why = audit_problems(allowed, before.as_bytes(), after.as_bytes());
        assert!(why.len() == 1 && why[0].contains(says), "{says}: {why:?}");
    }
    // The planted world's own stderr lines pass unremarked, and nothing else does.
    for (said, own) in [
        ("ai-env: LAB KNOBS ACTIVE (AI_ENV_BRIDGE_LAB_FAKE_API): not the real service (debug build)", true),
        ("ai-env: runtime key \u{2026}WXYZ (credentials/aws.env) (unsealed; the fake API does not use it)", true),
        ("ai-env: warning: /w/target/debug/ai-env-claude is under a build directory: cargo clean breaks Cursor; re-run ai-env wrapper install --write from the installed ai-env", true),
        ("ai-env: warning: audit row seed not written: denied", false),
        ("ai-env: reusing microvm-1", false),
    ] {
        assert_eq!(worlds_own(said), own, "{said}");
    }
    // A section ends at the next heading of its level, never at one inside a code block.
    let md = "## A\n\n```text\n# not a heading\n```\n\n### B\n\ntext\n\n## C\n";
    assert_eq!(section(md, "## A"), Some((1, "## A\n\n```text\n# not a heading\n```\n\n### B\n\ntext\n\n")));
    assert_eq!(section(md, "### B"), Some((7, "### B\n\ntext\n\n")));
    assert_eq!(section(md, "## C").map(|(n, _)| n), Some(11));
    assert_eq!(section(md, "## D"), None);
}
