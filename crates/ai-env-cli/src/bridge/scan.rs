//! `ai-env infra scan DIR` (S3 D7): the secret and settings scan every tree
//! passes before it leaves the Mac. S3 runs it on the staged image before
//! `make image-zip` zips it; S8 (seed) and S9 (`box review`) reuse
//! [`scan_dir`], [`Rules`] and [`Pattern`].
//!
//! Tripwires: the nine built-in patterns of [`DEFAULT_RULES`] (plan §10)
//! ALWAYS apply; `--tripwires FILE` (else `[review].tripwires` when that file
//! exists) only adds, one pattern per non-blank, non-`#` line (surrounding
//! whitespace trimmed; write `[ ]` for a significant edge space), rule id
//! `tripwire:LINE`. The built-ins carry a token tail (`sk-ant-` alone never
//! trips) so the staged shim binary, whose scrubber knows the bare prefixes,
//! stays clean; when a file named `ai-env` trips anyway the scan says the
//! pattern, not the binary, must change (D7).
//!
//! Pattern language, deliberately tiny so a reviewer can read every rule and
//! the matcher needs no `regex` crate: literal bytes, `.` (any byte but
//! newline), classes `[abc]`, `[a-z0-9_-]` (a `-` first or last is literal),
//! `[^/ @]`, the quantifiers `*`, `+`, `{n}`, `{n,}`, `{n,m}` (counts up to
//! [`MAX_COUNT`]) on the preceding atom, and `\` before ASCII punctuation.
//! Everything else is a load error naming the rule's source (built-in id or
//! `FILE:LINE`) and a column, never the pattern text (a tripwire may be a
//! literal secret): groups, alternation, `?`, anchors, `\d`-style escapes
//! (they would otherwise silently mean a letter), stacked quantifiers, an
//! unbalanced bracket or brace, `[` or a non-ASCII byte inside a class, a
//! quantifier after a non-ASCII byte (it would repeat one byte of the
//! character), and a pattern that matches the empty string (it would flag
//! every file). A match never spans a newline: the search is per line.
//!
//! Matching is linear in the line whatever the pattern, so a hostile or
//! careless tripwire cannot stall `make image-zip` on a binary: the leading
//! literal bytes are found by a plain byte search (on binaries nearly every
//! line is rejected there), and a line that holds them is decided by one
//! left-to-right pass that carries, per remaining atom, the leftmost start
//! reaching the current position (the minimum over the atom's window). No
//! backtracking: `a*a*a*b` on a megabyte of `a` costs one pass. Each atom
//! keeps only what its window can still use, so the scratch memory is
//! bounded by the pattern's counts, never by the line (a 64 MiB one-line
//! file costs no more than a short one).
//!
//! Image profile: the baked Claude config files get the settings rules of
//! [`settings_findings`] (among them: `.claude.json` bakes no project entry,
//! D5, and managed settings carry the four D6 hardening values of
//! [`crate::wire::managed`], the list `/validate` V3 checks too); the repo
//! profile is tripwires only. The walk never
//! follows a symlink (a symlink is itself a finding) and reports any node
//! that is neither a regular file nor a directory. It walks by descriptor:
//! every entry is opened relative to its parent directory's descriptor with
//! `O_NOFOLLOW`, and a directory must still be the node its `lstat` saw, so
//! a symlink swapped in during the scan is reported, never followed.
//!
//! Output names file, line and rule — NEVER the matched bytes or a JSON
//! value: the report lands in make logs and terminals, and a finding exists
//! precisely because the bytes may be a secret. Any finding is exit 9.
use crate::bridge::config::{BridgeConfig, Paths};
use crate::errors::CliError;
use crate::outln;
use crate::wire::managed::{hardening_gaps, MANAGED_HARDENING};
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsStr};
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Which rule set applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Profile {
    /// Tripwires plus the baked-settings rules (settings.json, managed-settings.json, .claude.json)
    Image,
    /// Tripwires only
    Repo,
}

/// Largest count a `{n}`, `{n,}` or `{n,m}` may name.
pub const MAX_COUNT: usize = 1000;

/// The built-in tripwires, `(rule id, pattern)` (plan §10); they always apply.
/// `private-key-block` and `mysql-pwd` escape one byte (`\ `, `\=`): the
/// escape matches the same inputs, but the pattern's own text no longer
/// matches it, so neither this file nor the compiled binary, which carries
/// every pattern verbatim, trips the scan (S8 seeds and S9 reviews
/// workspaces, this repo among them; unit-tested). `jwt` deviates from
/// the §10 text (`{20}` before the dot): a fixed count there only matched a
/// header of exactly 20 characters after `eyJ`, and the standard HS256 header
/// has 33, so `{20,}` is what catches real tokens.
pub const DEFAULT_RULES: [(&str, &str); 9] = [
    ("anthropic-key", "sk-ant-[a-z]{2,8}[0-9]{2}-[A-Za-z0-9_-]{20}"),
    ("aws-access-key-id", "AKIA[0-9A-Z]{16}"),
    ("private-key-block", "-----BEGIN .*PRIVATE\\ KEY"),
    // age's bech32 data charset in upper case (no 1, B, I or O): HTTP method names that follow the
    // literal in a binary's rodata (`GETTRACEPUTPATCHOPTIONS…`) are not a key.
    ("age-identity", "AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{20}"),
    ("mysql-pwd", "MYSQL_PWD\\="),
    ("github-pat", "ghp_[A-Za-z0-9]{20}"),
    ("slack-token", "xox[bp]-[A-Za-z0-9-]{10}"),
    ("jwt", "eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20}"),
    ("url-credentials", "://[^/ @:]+:[^/ @]+@"),
];

// ---- pattern ----------------------------------------------------------------

/// A set of bytes. `\n` is never a member, so no match can span two lines.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ByteSet([u64; 4]);

impl ByteSet {
    const EMPTY: ByteSet = ByteSet([0; 4]);

    fn has(&self, b: u8) -> bool {
        (self.0[usize::from(b >> 6)] >> (b & 63)) & 1 == 1
    }

    fn add(&mut self, b: u8) {
        self.0[usize::from(b >> 6)] |= 1 << (b & 63);
    }

    fn negated(self) -> ByteSet {
        ByteSet([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    fn without_newline(mut self) -> ByteSet {
        self.0[0] &= !(1 << b'\n');
        self
    }

    /// The only member, when there is exactly one (a literal byte).
    fn single(&self) -> Option<u8> {
        if self.0.iter().map(|w| w.count_ones()).sum::<u32>() != 1 {
            return None;
        }
        (0..=255u8).find(|b| self.has(*b))
    }
}

/// One atom and its repetition bounds (`max == usize::MAX`: unbounded).
#[derive(Clone)]
struct Atom {
    set: ByteSet,
    min: usize,
    max: usize,
}

/// A compiled tripwire pattern (language in the module docs). `Debug` shows
/// sizes only: a tripwire may be a literal secret.
#[derive(Clone)]
pub struct Pattern {
    /// Leading literal bytes: the fast path, searched before any line work.
    prefix: Vec<u8>,
    /// Everything after the prefix.
    rest: Vec<Atom>,
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pattern {{ prefix: {} bytes, atoms: {} }}", self.prefix.len(), self.rest.len())
    }
}

/// The byte after a `\`: ASCII punctuation (or space) only, so `\d`, `\n`,
/// `\s` are refused instead of silently meaning a letter.
fn escaped(b: &[u8], at: usize) -> Result<u8, String> {
    match b.get(at + 1) {
        None => Err(format!("trailing backslash at column {}", at + 1)),
        Some(&c) if c.is_ascii() && !c.is_ascii_alphanumeric() && c != b'\n' => Ok(c),
        Some(_) => Err(format!("unsupported escape at column {} (only ASCII punctuation may follow a backslash)", at + 1)),
    }
}

/// One member byte of a class at `at`, and the index after it.
fn class_byte(b: &[u8], at: usize) -> Result<(u8, usize), String> {
    match b[at] {
        b'\\' => Ok((escaped(b, at)?, at + 2)),
        b'[' => Err(format!("unescaped '[' inside a class at column {} (write \\[)", at + 1)),
        b'\n' => Err(format!("newline in pattern at column {}", at + 1)),
        c if !c.is_ascii() => Err(format!("non-ASCII byte inside a class at column {}", at + 1)),
        c => Ok((c, at + 1)),
    }
}

/// `[...]` starting at `open`: the set (newline removed) and the index after `]`.
fn parse_class(b: &[u8], open: usize) -> Result<(ByteSet, usize), String> {
    let mut i = open + 1;
    let negate = b.get(i) == Some(&b'^');
    if negate {
        i += 1;
    }
    let first = i;
    let mut set = ByteSet::EMPTY;
    loop {
        let Some(&c) = b.get(i) else {
            return Err(format!("unbalanced '[' at column {}", open + 1));
        };
        if c == b']' {
            break;
        }
        let (lo, next) = class_byte(b, i)?;
        i = next;
        let is_range = |at: usize| b.get(at) == Some(&b'-') && b.get(at + 1).is_some_and(|n| *n != b']');
        if is_range(i) {
            let (hi, next) = class_byte(b, i + 1)?;
            if hi < lo {
                return Err(format!("reversed range at column {}", i));
            }
            for x in lo..=hi {
                set.add(x);
            }
            i = next;
            if is_range(i) {
                return Err(format!("ambiguous '-' at column {} (escape it as \\-)", i + 1));
            }
        } else {
            set.add(lo);
        }
    }
    if i == first {
        return Err(format!("empty class at column {}", open + 1));
    }
    let set = if negate { set.negated() } else { set }.without_newline();
    if set == ByteSet::EMPTY {
        return Err(format!("class at column {} matches nothing", open + 1));
    }
    Ok((set, i + 1))
}

/// A decimal count of a `{...}` (at most [`MAX_COUNT`]).
fn count(digits: &[u8], col: usize) -> Result<usize, String> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(format!("bad count at column {col} (use {{n}}, {{n,}} or {{n,m}})"));
    }
    let n = digits.iter().fold(0usize, |acc, d| acc.saturating_mul(10).saturating_add(usize::from(d - b'0')));
    if n > MAX_COUNT {
        return Err(format!("count at column {col} is above {MAX_COUNT}"));
    }
    Ok(n)
}

/// `{n}`, `{n,}` or `{n,m}` starting at `open`: `(min, max, index after })`.
fn parse_count(b: &[u8], open: usize) -> Result<(usize, usize, usize), String> {
    let col = open + 1;
    let Some(close) = b[open..].iter().position(|c| *c == b'}').map(|p| open + p) else {
        return Err(format!("unbalanced '{{' at column {col}"));
    };
    let body = &b[open + 1..close];
    let (min, max) = match body.iter().position(|c| *c == b',') {
        None => {
            let n = count(body, col)?;
            (n, n)
        }
        Some(k) if k + 1 == body.len() => (count(&body[..k], col)?, usize::MAX),
        Some(k) => (count(&body[..k], col)?, count(&body[k + 1..], col)?),
    };
    if max < min {
        return Err(format!("count at column {col} has min {min} above max {max}"));
    }
    Ok((min, max, close + 1))
}

impl Pattern {
    /// Compile `src`. The error names a column and the construct, never the
    /// pattern text; callers prefix the rule's source.
    pub fn parse(src: &str) -> Result<Pattern, String> {
        let b = src.as_bytes();
        if b.is_empty() {
            return Err("empty pattern".into());
        }
        let mut atoms: Vec<Atom> = Vec::new();
        // The last atom already carries a quantifier / is one byte of a
        // multi-byte character.
        let mut quantified = false;
        let mut non_ascii = false;
        let mut i = 0;
        while i < b.len() {
            let col = i + 1;
            let c = b[i];
            if matches!(c, b'*' | b'+' | b'{') {
                let (min, max, next) = match c {
                    b'*' => (0, usize::MAX, i + 1),
                    b'+' => (1, usize::MAX, i + 1),
                    _ => parse_count(b, i)?,
                };
                let Some(last) = atoms.last_mut() else {
                    return Err(format!("quantifier '{}' at column {col} has nothing to repeat", char::from(c)));
                };
                if quantified {
                    return Err(format!("stacked quantifier '{}' at column {col}", char::from(c)));
                }
                if non_ascii {
                    return Err(format!("quantifier '{}' at column {col} follows a non-ASCII byte (it would repeat one byte of the character)", char::from(c)));
                }
                last.min = min;
                last.max = max;
                quantified = true;
                i = next;
                continue;
            }
            let (set, next) = match c {
                b'.' => (ByteSet::EMPTY.negated().without_newline(), i + 1),
                b'[' => parse_class(b, i)?,
                b'\\' => {
                    let mut s = ByteSet::EMPTY;
                    s.add(escaped(b, i)?);
                    (s, i + 2)
                }
                b']' | b'}' => return Err(format!("unbalanced '{}' at column {col}", char::from(c))),
                b'(' | b')' | b'|' | b'?' | b'^' | b'$' => {
                    return Err(format!("unsupported '{}' at column {col} (no groups, alternation, '?' or anchors; escape it with \\)", char::from(c)))
                }
                b'\n' => return Err(format!("newline in pattern at column {col}")),
                _ => {
                    let mut s = ByteSet::EMPTY;
                    s.add(c);
                    (s, i + 1)
                }
            };
            atoms.push(Atom { set, min: 1, max: 1 });
            quantified = false;
            non_ascii = !c.is_ascii();
            i = next;
        }
        atoms.retain(|a| a.max > 0);
        if atoms.iter().all(|a| a.min == 0) {
            return Err("pattern matches the empty string (it would flag every file)".into());
        }
        let mut prefix = Vec::new();
        let mut k = 0;
        while let Some(a) = atoms.get(k) {
            match a.set.single() {
                Some(byte) if a.min == a.max => prefix.extend(std::iter::repeat_n(byte, a.min)),
                _ => break,
            }
            k += 1;
        }
        let rest = atoms.split_off(k);
        Ok(Pattern { prefix, rest })
    }

    /// Byte offset of the leftmost match in `hay`, searched line by line (a
    /// match never contains `\n`).
    #[must_use]
    pub fn find(&self, hay: &[u8]) -> Option<usize> {
        let mut from = 0;
        while from <= hay.len() {
            let start = if self.prefix.is_empty() { from } else { find_literal(hay, from, &self.prefix)? };
            let end = find_byte(hay, start, b'\n').unwrap_or(hay.len());
            if let Some(s) = self.leftmost_in_line(&hay[start..end]) {
                return Some(start + s);
            }
            from = end + 1;
        }
        None
    }

    /// 1-based numbers of the lines of `hay` that hold at least one match.
    #[must_use]
    pub fn matching_lines(&self, hay: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let (mut from, mut line, mut counted) = (0, 1, 0);
        while from <= hay.len() {
            let Some(at) = self.find(&hay[from..]).map(|s| from + s) else {
                break;
            };
            line += count_byte(&hay[counted..at], b'\n');
            counted = at;
            out.push(line);
            match find_byte(hay, at, b'\n') {
                Some(nl) => from = nl + 1,
                None => break,
            }
        }
        out
    }

    /// Leftmost match start in `seg` (one line, or its tail from the first
    /// prefix hit), in one left-to-right pass: at each position `q` the start
    /// of a prefix occurrence ending at `q` (every `q` when there is no
    /// prefix) is fed through one [`Stage`] per atom. With nothing in flight
    /// the pass jumps to the next prefix occurrence, and it stops once a match
    /// is known and no earlier start is still in flight.
    fn leftmost_in_line(&self, seg: &[u8]) -> Option<usize> {
        self.leftmost_with(seg, &mut Vec::new())
    }

    /// [`Pattern::leftmost_in_line`] on caller-owned stages (a test reads their capacity).
    fn leftmost_with(&self, seg: &[u8], stages: &mut Vec<Stage>) -> Option<usize> {
        if self.rest.is_empty() {
            return Some(0); // a pure literal: `seg` starts at its occurrence
        }
        stages.clear();
        stages.extend(self.rest.iter().map(Stage::new));
        let plen = self.prefix.len();
        // The next prefix occurrence not fed yet; it always ends at or after `q`.
        let mut next = if plen == 0 { None } else { find_literal(seg, 0, &self.prefix) };
        let mut found = NONE;
        // A start went in at the last position: skip the idle check once (it
        // only decides a shortcut, never a result).
        let mut fed = false;
        let mut q = 0;
        while q <= seg.len() {
            if !fed && stages[0].idle() && stages.iter().all(Stage::idle) {
                if found != NONE {
                    break; // every later start lies right of `found`
                }
                if plen > 0 {
                    let Some(at) = next else { break };
                    q = q.max(at + plen);
                }
            }
            // Once a match is known no new start can beat it: only drain what is in flight.
            let mut v = NONE;
            if found == NONE {
                if plen == 0 {
                    v = q;
                } else if let Some(at) = next.filter(|at| at + plen == q) {
                    v = at;
                    next = find_literal(seg, at + 1, &self.prefix);
                }
            }
            fed = v != NONE;
            for stage in stages.iter_mut() {
                v = stage.step(seg, q, v);
            }
            found = found.min(v);
            q += 1;
        }
        (found != NONE).then_some(found)
    }
}

/// No start: no partial match reaches this position.
const NONE: usize = usize::MAX;

/// One atom's state in the pass of [`Pattern::leftmost_with`]. At position
/// `q` it reads `s[q]`, the leftmost start from which the earlier atoms match
/// `seg[start..q]`, and yields the minimum of `s[p]` over its window
/// `q - max <= p <= q - min` with `seg[p..q]` inside the atom's set.
///
/// Starts only grow along the line: the first stage is fed prefix
/// occurrences in order, and a window's lower end never moves left, so each
/// stage passes on a non-decreasing sequence too. The minimum of a window is
/// therefore its oldest input: a bounded atom keeps the inputs of its last
/// `max + 1` positions, an unbounded one only the first input since its run
/// began. That is the whole scratch, whatever the length of the line.
struct Stage {
    atom: Atom,
    /// Whether the byte before `q` is in the set (`seg[q]` as seen by the
    /// previous step). After a jump it may be stale, but then the stage is
    /// idle and the reset it drives changes nothing.
    in_set: bool,
    /// Bounded atom: inputs `(p, s[p])` with `q - max <= p <= q`, oldest first.
    queue: VecDeque<(usize, usize)>,
    /// Unbounded atom: the first input of the run, until it enters the window at `p + min`.
    pending: Option<(usize, usize)>,
    /// Unbounded atom: the value of the first input of the run that entered the window.
    best: usize,
}

impl Stage {
    fn new(atom: &Atom) -> Stage {
        Stage { atom: atom.clone(), in_set: true, queue: VecDeque::new(), pending: None, best: NONE }
    }

    /// No partial match in flight.
    fn idle(&self) -> bool {
        self.queue.is_empty() && self.pending.is_none() && self.best == NONE
    }

    /// Feed `input` = `s[q]` (`NONE`: no partial match ends at `q`) and
    /// return the stage's value at `q`. Called for consecutive `q` while not
    /// idle (an idle stage fed `NONE` stays idle, so skipped positions are safe).
    fn step(&mut self, seg: &[u8], q: usize, mut input: usize) -> usize {
        let atom = &self.atom;
        if !self.in_set {
            // No run of the set crosses `q - 1`: nothing held can reach `q` or beyond.
            if !self.queue.is_empty() {
                self.queue.clear();
            }
            self.pending = None;
            self.best = NONE;
        }
        self.in_set = q < seg.len() && atom.set.has(seg[q]);
        // An input that needs another byte of the set, where the next byte is
        // not one, can never enter the window: drop it now rather than hold it
        // until the reset at `q + 1`.
        if atom.min > 0 && !self.in_set {
            input = NONE;
        }
        if atom.max == usize::MAX {
            // Later inputs of the run can never beat the first one.
            if input != NONE && self.best == NONE && self.pending.is_none() {
                self.pending = Some((q, input));
            }
            if let Some((_, v)) = self.pending.filter(|&(p, _)| p + atom.min == q) {
                self.best = v;
                self.pending = None;
            }
            return self.best;
        }
        if input != NONE {
            self.queue.push_back((q, input));
        } else if self.queue.is_empty() {
            return NONE;
        }
        let lo = q.saturating_sub(atom.max);
        while self.queue.front().is_some_and(|f| f.0 < lo) {
            self.queue.pop_front();
        }
        match self.queue.front() {
            Some(&(p, v)) if p + atom.min <= q => v,
            _ => NONE,
        }
    }
}

/// First occurrence of `lit` (non-empty) in `hay` at or after `from`.
fn find_literal(hay: &[u8], from: usize, lit: &[u8]) -> Option<usize> {
    let last = hay.len().checked_sub(lit.len())?;
    let first = lit[0];
    let mut i = from;
    while i <= last {
        if hay[i] == first && hay[i..i + lit.len()] == *lit {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_byte(hay: &[u8], from: usize, byte: u8) -> Option<usize> {
    let mut i = from;
    while i < hay.len() {
        if hay[i] == byte {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn count_byte(hay: &[u8], byte: u8) -> usize {
    let mut n = 0;
    for b in hay {
        n += usize::from(*b == byte);
    }
    n
}

// ---- rules ------------------------------------------------------------------

struct Rule {
    id: String,
    pattern: Pattern,
}

/// The tripwire set: the built-ins, then the extras of one tripwires file.
/// `Debug` lists the rule ids only.
pub struct Rules {
    rules: Vec<Rule>,
}

impl std::fmt::Debug for Rules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.ids()).finish()
    }
}

impl Rules {
    /// The built-ins alone ([`DEFAULT_RULES`]).
    #[must_use]
    pub fn defaults() -> Rules {
        Rules { rules: compile_built_ins(&DEFAULT_RULES) }
    }

    /// The built-ins plus one pattern per non-blank, non-`#` line of `text`
    /// (rule id `tripwire:LINE`). A bad line is an error naming `source:LINE`.
    pub fn with_extras(text: &str, source: &str) -> Result<Rules, String> {
        let mut rules = Rules::defaults();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let pattern = Pattern::parse(line).map_err(|e| format!("{source}:{}: {e}", n + 1))?;
            rules.rules.push(Rule { id: format!("tripwire:{}", n + 1), pattern });
        }
        Ok(rules)
    }

    /// [`Rules::with_extras`] over a file that must exist.
    pub fn from_file(path: &Path) -> Result<Rules, String> {
        Rules::with_extras(&read_list(path)?, &path.display().to_string())
    }

    /// Rule ids in evaluation order (built-ins first).
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.id.as_str())
    }

    /// `(line, rule id)` for every line of `hay` that a rule matches, one
    /// entry per rule and line, grouped by rule.
    #[must_use]
    pub fn scan_bytes(&self, hay: &[u8]) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        for r in &self.rules {
            out.extend(r.pattern.matching_lines(hay).into_iter().map(|line| (line, r.id.clone())));
        }
        out
    }
}

/// Compile a table of built-ins. Each parses (unit-tested); if one ever does
/// not, that is a bug and the panic names its rule id.
fn compile_built_ins(table: &[(&str, &str)]) -> Vec<Rule> {
    table
        .iter()
        .map(|(id, src)| Rule { id: (*id).to_string(), pattern: Pattern::parse(src).unwrap_or_else(|e| panic!("built-in tripwire {id}: {e}")) })
        .collect()
}

/// A tripwire rule id (built-in or `tripwire:N`), as opposed to the walk and settings rules.
fn is_tripwire(rule: &str) -> bool {
    rule.starts_with("tripwire:") || DEFAULT_RULES.iter().any(|(id, _)| *id == rule)
}

/// `allow <entry>` lines of a settings policy (blank and `#` lines skipped).
/// Any other line is an error naming `source:LINE` but never its text: allow
/// rules have been seen carrying credentials.
pub fn parse_policy(text: &str, source: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.strip_prefix("allow ").map(str::trim) {
            Some(entry) if !entry.is_empty() => out.push(entry.to_string()),
            _ => return Err(format!("{source}:{}: expected `allow <entry>`", n + 1)),
        }
    }
    Ok(out)
}

/// A list file named on the command line: it must exist.
fn read_list(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// A list file from `[review]` defaults: `None` when it does not exist (the
/// documented setup is an empty `[review]` table and no files).
fn read_default_list(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

// ---- settings rules -----------------------------------------------------------

const SETTINGS_KEYS: [&str; 6] = ["$schema", "permissions", "env", "model", "includeCoAuthoredBy", "cleanupPeriodDays"];
const MANAGED_KEYS: [&str; 2] = ["permissions", "env"];
const PERMISSIONS_KEYS: [&str; 7] = ["allow", "deny", "ask", "defaultMode", "disableBypassPermissionsMode", "disableAutoMode", "additionalDirectories"];
const CONFIG_KEYS: [&str; 2] = ["hasCompletedOnboarding", "projects"];
const DEFAULT_MODES: [&str; 2] = ["default", "plan"];
/// Refused whatever the policy says.
const BROAD_ALLOW: [&str; 5] = ["Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)", "*"];
/// An `env` name containing one of these (any case) is refused: the baked
/// config must never carry a credential, and a name is enough to tell.
const SECRET_ENV_WORDS: [&str; 6] = ["TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL"];
const BYPASS: &str = "bypassPermissions";

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonKind {
    /// `settings.json`, `settings.local.json`
    Settings,
    /// `managed-settings.json`
    Managed,
    /// `claude.json`, `.claude.json`
    Config,
}

fn json_kind(name: &str) -> Option<JsonKind> {
    match name {
        "settings.json" | "settings.local.json" => Some(JsonKind::Settings),
        "managed-settings.json" => Some(JsonKind::Managed),
        "claude.json" | ".claude.json" => Some(JsonKind::Config),
        _ => None,
    }
}

/// One rule id per D6 value, in `MANAGED_HARDENING` order: the id names the
/// key path (never a value), so each gap is its own finding. Sized by the
/// shared list: a D6 value added there does not compile until it has a rule.
pub const MANAGED_RULES: [&str; MANAGED_HARDENING.len()] = [
    "managed-hardening:permissions.disableBypassPermissionsMode",
    "managed-hardening:permissions.disableAutoMode",
    "managed-hardening:env.DISABLE_AUTOUPDATER",
    "managed-hardening:env.DISABLE_UPDATES",
];

/// The settings rules for a file named `file_name` (empty for any other
/// name), as `(line, rule)`. Semantics come from serde_json (duplicate keys:
/// the last wins, as in Claude's own parser); lines come from [`Located`], a
/// walk over the same bytes, and are the 1-based line of the offending key,
/// allow entry or `bypassPermissions` string. Line 0 means the file as a
/// whole: valid JSON whose root is not an object (a syntax error carries the
/// parser's line), or a place the walk could not pin down.
///
/// Settings and managed settings: top-level and `permissions` keys limited
/// (`unexpected-key`); `permissions`/`env` must be objects
/// (`not-json-object`); `defaultMode` is `default` or `plan`
/// (`default-mode`); allow entries are never [`BROAD_ALLOW`] (`broad-allow`)
/// and otherwise must equal a policy entry (`allow-not-in-policy`, also for
/// a non-array `allow` or a non-string entry); no secret-looking `env` name
/// (`secret-env-name`). Managed settings: every D6 value of
/// [`crate::wire::managed::MANAGED_HARDENING`] present and equal
/// (`managed-hardening:<path>`, [`MANAGED_RULES`], at the key's line, 0
/// when it is absent). Config
/// files: only `hasCompletedOnboarding` and `projects`, the latter an object
/// without entries (`project-entry` at each entry's key: v0 bakes none, D5;
/// a trusted project would carry its own allow list and MCP servers past the
/// rules above). Every kind: any string VALUE equal to `bypassPermissions`
/// (`bypass-permissions`).
#[must_use]
pub fn settings_findings(file_name: &str, bytes: &[u8], policy: &[String]) -> Vec<(usize, &'static str)> {
    let Some(kind) = json_kind(file_name) else {
        return Vec::new();
    };
    let root: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => return vec![(e.line(), "not-json-object")],
    };
    let Some(obj) = root.as_object() else {
        return vec![(0, "not-json-object")];
    };
    let at = Located::walk(bytes);
    let mut out = Vec::new();
    let top: &[&str] = match kind {
        JsonKind::Settings => &SETTINGS_KEYS,
        JsonKind::Managed => &MANAGED_KEYS,
        JsonKind::Config => &CONFIG_KEYS,
    };
    for k in obj.keys() {
        if !top.contains(&k.as_str()) {
            out.push((at.key_line(&[k]), "unexpected-key"));
        }
    }
    if kind == JsonKind::Config {
        match obj.get("projects").map(Value::as_object) {
            None => {}
            Some(None) => out.push((at.key_line(&["projects"]), "not-json-object")),
            Some(Some(entries)) => {
                for k in entries.keys() {
                    out.push((at.key_line(&["projects", k]), "project-entry"));
                }
            }
        }
    } else {
        if kind == JsonKind::Managed {
            let gaps = hardening_gaps(&root);
            for ((path, _), rule) in MANAGED_HARDENING.iter().zip(MANAGED_RULES) {
                if gaps.contains(&path.join(".")) {
                    out.push((at.key_line(path), rule));
                }
            }
        }
        if let Some(perms) = obj.get("permissions") {
            permissions_findings(perms, &at, policy, &mut out);
        }
        match obj.get("env").map(Value::as_object) {
            None => {}
            Some(None) => out.push((at.key_line(&["env"]), "not-json-object")),
            Some(Some(vars)) => {
                for name in vars.keys() {
                    let upper = name.to_ascii_uppercase();
                    if SECRET_ENV_WORDS.iter().any(|w| upper.contains(w)) {
                        out.push((at.key_line(&["env", name]), "secret-env-name"));
                    }
                }
            }
        }
    }
    let lines = at.string_lines(BYPASS);
    if count_strings(&root, BYPASS) > lines.len() {
        out.push((0, "bypass-permissions"));
    }
    out.extend(lines.into_iter().map(|l| (l, "bypass-permissions")));
    out
}

fn permissions_findings(perms: &Value, at: &Located, policy: &[String], out: &mut Vec<(usize, &'static str)>) {
    let Some(p) = perms.as_object() else {
        out.push((at.key_line(&["permissions"]), "not-json-object"));
        return;
    };
    for k in p.keys() {
        if !PERMISSIONS_KEYS.contains(&k.as_str()) {
            out.push((at.key_line(&["permissions", k]), "unexpected-key"));
        }
    }
    if p.get("defaultMode").is_some_and(|m| !m.as_str().is_some_and(|m| DEFAULT_MODES.contains(&m))) {
        out.push((at.key_line(&["permissions", "defaultMode"]), "default-mode"));
    }
    match p.get("allow").map(Value::as_array) {
        None => {}
        Some(None) => out.push((at.key_line(&["permissions", "allow"]), "allow-not-in-policy")),
        Some(Some(entries)) => {
            for (i, e) in entries.iter().enumerate() {
                let rule = match e.as_str() {
                    Some(s) if BROAD_ALLOW.contains(&s) => "broad-allow",
                    Some(s) if policy.iter().any(|p| p == s) => continue,
                    _ => "allow-not-in-policy",
                };
                out.push((at.item_line(&["permissions", "allow"], i), rule));
            }
        }
    }
}

/// String values equal to `needle` anywhere in `v` (keys excluded).
fn count_strings(v: &Value, needle: &str) -> usize {
    match v {
        Value::String(s) => usize::from(s == needle),
        Value::Array(a) => a.iter().map(|x| count_strings(x, needle)).sum(),
        Value::Object(o) => o.values().map(|x| count_strings(x, needle)).sum(),
        _ => 0,
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Seg {
    Key(String),
    Index(usize),
}

/// One object key (`string == None`) or string value, with its path and line.
struct Loc {
    path: Vec<Seg>,
    line: usize,
    string: Option<String>,
}

/// Where every key and string value of a JSON document sits. Only run on
/// bytes serde_json already accepted (so nesting is bounded by its recursion
/// limit); on anything unexpected it stops and keeps what it found.
struct Located(Vec<Loc>);

struct Walker<'a> {
    b: &'a [u8],
    i: usize,
    line: usize,
    path: Vec<Seg>,
    out: Vec<Loc>,
}

impl Walker<'_> {
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            match c {
                b'\n' => self.line += 1,
                b' ' | b'\t' | b'\r' => {}
                _ => return,
            }
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    /// The string token at `i` (which is `"`), decoded by serde_json.
    fn string(&mut self) -> Option<String> {
        let start = self.i;
        self.i += 1;
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                b'\\' => self.i += 1,
                b'"' => return serde_json::from_slice(&self.b[start..self.i]).ok(),
                _ => {}
            }
        }
        None
    }

    fn value(&mut self) -> Option<()> {
        self.ws();
        match self.peek()? {
            b'{' => {
                self.i += 1;
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Some(());
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return None;
                    }
                    let line = self.line;
                    let key = self.string()?;
                    self.path.push(Seg::Key(key));
                    self.out.push(Loc { path: self.path.clone(), line, string: None });
                    self.ws();
                    if self.peek() != Some(b':') {
                        return None;
                    }
                    self.i += 1;
                    self.value()?;
                    self.path.pop();
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.i += 1;
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Some(());
                }
                let mut index = 0;
                loop {
                    self.path.push(Seg::Index(index));
                    self.value()?;
                    self.path.pop();
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                    index += 1;
                }
            }
            b'"' => {
                let line = self.line;
                let s = self.string()?;
                self.out.push(Loc { path: self.path.clone(), line, string: Some(s) });
                Some(())
            }
            _ => {
                while self.peek().is_some_and(|c| !matches!(c, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n')) {
                    self.i += 1;
                }
                Some(())
            }
        }
    }
}

impl Seg {
    fn is_key(&self, k: &str) -> bool {
        matches!(self, Seg::Key(x) if x == k)
    }
}

impl Located {
    fn walk(bytes: &[u8]) -> Located {
        let mut w = Walker { b: bytes, i: 0, line: 1, path: Vec::new(), out: Vec::new() };
        let _ = w.value();
        Located(w.out)
    }

    /// Line of the key at `keys` (the last duplicate, as serde_json keeps), else 0.
    fn key_line(&self, keys: &[&str]) -> usize {
        self.0
            .iter()
            .rev()
            .find(|l| l.string.is_none() && l.path.len() == keys.len() && l.path.iter().zip(keys).all(|(s, k)| s.is_key(k)))
            .map_or(0, |l| l.line)
    }

    /// Line of the string at `keys[index]`, else of the array's key.
    fn item_line(&self, keys: &[&str], index: usize) -> usize {
        self.0
            .iter()
            .rev()
            .find(|l| {
                l.string.is_some()
                    && l.path.len() == keys.len() + 1
                    && l.path.iter().zip(keys).all(|(s, k)| s.is_key(k))
                    && l.path.last() == Some(&Seg::Index(index))
            })
            .map_or_else(|| self.key_line(keys), |l| l.line)
    }

    /// Lines of every string value equal to `value` (duplicates included).
    fn string_lines(&self, value: &str) -> Vec<usize> {
        self.0.iter().filter(|l| l.string.as_deref() == Some(value)).map(|l| l.line).collect()
    }
}

// ---- walk -------------------------------------------------------------------

/// One finding: where and which rule — never what matched. `line` is 1-based;
/// 0 means the file as a whole (`symlink`, `special-file`, see [`settings_findings`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
}

/// Scan the tree under `dir` (which must be a directory; a symlink given as
/// `dir` itself is followed, nothing below it is). Returns the findings,
/// sorted and deduplicated, and the number of regular files scanned. An
/// unreadable entry is an error: a file the scan cannot read is not clean.
pub fn scan_dir(dir: &Path, profile: Profile, rules: &Rules, policy: &[String]) -> Result<(Vec<Finding>, usize), String> {
    let meta = std::fs::metadata(dir).map_err(|e| format!("cannot scan {}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("cannot scan {}: not a directory", dir.display()));
    }
    // Only the root is resolved by path; everything below is opened relative
    // to its parent's descriptor.
    let root = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(dir).map_err(|e| format!("cannot scan {}: {e}", dir.display()))?;
    let mut walk = Walk { profile, rules, policy, findings: Vec::new(), files: 0 };
    walk.dir(root.as_fd(), dir, "")?;
    let Walk { mut findings, files, .. } = walk;
    findings.sort();
    findings.dedup();
    Ok((findings, files))
}

struct Walk<'a> {
    profile: Profile,
    rules: &'a Rules,
    policy: &'a [String],
    findings: Vec<Finding>,
    files: usize,
}

impl Walk<'_> {
    /// Scan the directory open as `dir`: `path` names it in errors, `rel` in
    /// findings (empty at the root). Each entry is classified by an `lstat`
    /// relative to `dir` (a special file is never opened) and then opened
    /// relative to `dir` without following a symlink.
    fn dir(&mut self, dir: BorrowedFd<'_>, path: &Path, rel: &str) -> Result<(), String> {
        let mut names = list_dir(dir).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        names.sort();
        for name in names {
            let os = OsStr::from_bytes(name.to_bytes());
            let child = path.join(os);
            let rel = if rel.is_empty() { shown(os) } else { format!("{rel}/{}", shown(os)) };
            let seen = stat_at(dir, &name).map_err(|e| format!("cannot stat {}: {e}", child.display()))?;
            match seen.st_mode & libc::S_IFMT {
                libc::S_IFLNK => self.push(&rel, 0, "symlink"),
                libc::S_IFDIR => self.subdir(dir, &name, &seen, &child, &rel)?,
                libc::S_IFREG => self.file(dir, &name, &child, &rel)?,
                _ => self.push(&rel, 0, "special-file"),
            }
        }
        Ok(())
    }

    /// Enter the directory `name` of `parent`, which the `lstat` saw as
    /// `seen`. It is opened with `O_NOFOLLOW` and must still be that node
    /// (device and inode): anything swapped in since the `lstat` (a symlink,
    /// refused by the open with `ENOTDIR` on macOS and current Linux, `ELOOP`
    /// on older kernels; a file; another directory) is reported as `symlink`
    /// and not entered.
    fn subdir(&mut self, parent: BorrowedFd<'_>, name: &CStr, seen: &libc::stat, path: &Path, rel: &str) -> Result<(), String> {
        let fd = match open_at(parent, name, libc::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
                self.push(rel, 0, "symlink");
                return Ok(());
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let now = stat_fd(fd.as_fd()).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if (now.st_dev, now.st_ino) != (seen.st_dev, seen.st_ino) {
            self.push(rel, 0, "symlink");
            return Ok(());
        }
        self.dir(fd.as_fd(), path, rel)
    }

    fn file(&mut self, dir: BorrowedFd<'_>, name: &CStr, path: &Path, rel: &str) -> Result<(), String> {
        let bytes = match read_regular(dir, name) {
            Ok(Some(b)) => b,
            Ok(None) => {
                self.push(rel, 0, "special-file");
                return Ok(());
            }
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                self.push(rel, 0, "symlink");
                return Ok(());
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        self.files += 1;
        for (line, rule) in self.rules.scan_bytes(&bytes) {
            self.findings.push(Finding { file: rel.to_string(), line, rule });
        }
        if self.profile == Profile::Image {
            let file_name = OsStr::from_bytes(name.to_bytes()).to_string_lossy();
            for (line, rule) in settings_findings(&file_name, &bytes, self.policy) {
                self.push(rel, line, rule);
            }
        }
        Ok(())
    }

    fn push(&mut self, rel: &str, line: usize, rule: &str) {
        self.findings.push(Finding { file: rel.to_string(), line, rule: rule.to_string() });
    }
}

/// A name as reported: lossy UTF-8, control characters shown as `?` so a
/// crafted name cannot forge report lines.
fn shown(name: &OsStr) -> String {
    name.to_string_lossy().chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// Open `name` of `dir` without following a symlink and without blocking on a
/// FIFO swapped in since the `lstat`; `None` when the opened node is not a
/// regular file.
fn read_regular(dir: BorrowedFd<'_>, name: &CStr) -> std::io::Result<Option<Vec<u8>>> {
    let mut file = std::fs::File::from(open_at(dir, name, libc::O_NONBLOCK)?);
    if !file.metadata()?.file_type().is_file() {
        return Ok(None);
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(Some(buf))
}

// ---- descriptors --------------------------------------------------------------

/// `lstat` of `name` inside the directory open as `dir` (fstatat(2) with
/// `AT_SYMLINK_NOFOLLOW`).
fn stat_at(dir: BorrowedFd<'_>, name: &CStr) -> std::io::Result<libc::stat> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir` is an open descriptor (borrowed for the call), `name` is
    // NUL-terminated and outlives the call, and `st` is writable memory for
    // one `struct stat`.
    let rc = unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstatat(2) returned 0, so it filled `st`.
    Ok(unsafe { st.assume_init() })
}

/// fstat(2) of an open descriptor.
fn stat_fd(fd: BorrowedFd<'_>) -> std::io::Result<libc::stat> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is an open descriptor (borrowed for the call) and `st` is
    // writable memory for one `struct stat`.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstat(2) returned 0, so it filled `st`.
    Ok(unsafe { st.assume_init() })
}

/// openat(2) of `name` inside the directory open as `dir`: read-only,
/// close-on-exec, and never through a symlink (`O_NOFOLLOW` guards the last
/// component, and `dir` itself was opened the same way), plus `flags`.
fn open_at(dir: BorrowedFd<'_>, name: &CStr, flags: libc::c_int) -> std::io::Result<OwnedFd> {
    // SAFETY: `dir` is an open descriptor (borrowed for the call) and `name` is
    // NUL-terminated and outlives it; without O_CREAT no mode argument is read.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat(2) returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The entry names of the directory open as `dir`, without `.` and `..`, in
/// no particular order.
fn list_dir(dir: BorrowedFd<'_>) -> std::io::Result<Vec<CString>> {
    // fdopendir(3) takes over the descriptor it is given (closedir closes it):
    // hand it a duplicate so `dir` stays open for the *at calls.
    let raw = dir.try_clone_to_owned()?.into_raw_fd();
    // SAFETY: `raw` is an open directory descriptor owned by this function.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        let e = std::io::Error::last_os_error();
        // SAFETY: fdopendir(3) failed, so `raw` is still open and ours; OwnedFd closes it once.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        return Err(e);
    }
    let mut names = Vec::new();
    let listed = loop {
        // readdir(3) returns NULL at the end and on an error alike; only a
        // cleared errno tells the two apart.
        clear_errno();
        // SAFETY: `stream` is a live DIR from fdopendir(3), used by this thread
        // only and closed after the loop.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let e = std::io::Error::last_os_error();
            let end = e.raw_os_error() == Some(0);
            break if end { Ok(names) } else { Err(e) };
        }
        // SAFETY: a non-NULL entry stays valid until the next readdir/closedir
        // on `stream`, and `d_name` is NUL-terminated inside it. It is reached
        // through a raw pointer (the record may be shorter than
        // `struct dirent`) and copied out at once.
        let name = unsafe { CStr::from_ptr((&raw const (*entry).d_name).cast::<libc::c_char>()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    };
    // SAFETY: `stream` came from fdopendir(3) and is closed exactly once here,
    // which also closes `raw`.
    unsafe { libc::closedir(stream) };
    listed
}

/// Set this thread's errno to 0.
#[cfg(target_vendor = "apple")]
fn clear_errno() {
    // SAFETY: __error() returns this thread's errno slot, writable for the thread's life.
    unsafe { *libc::__error() = 0 };
}

/// Set this thread's errno to 0.
#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: __errno_location() returns this thread's errno slot, writable for the thread's life.
    unsafe { *libc::__errno_location() = 0 };
}

// ---- command ----------------------------------------------------------------

#[derive(Serialize)]
struct Report<'a> {
    dir: String,
    clean: bool,
    files: usize,
    findings: &'a [Finding],
}

/// `ai-env infra scan DIR`: exit 0 and `scan: clean (N files)`, or one
/// `RELPATH:LINE: RULE` line per finding, a summary, and exit 9. A missing
/// explicit list file, a bad pattern or policy line, or a bad DIR is exit 1.
pub fn cmd_scan(dir: &Path, profile: Profile, tripwires: Option<&Path>, settings_policy: Option<&Path>, json: bool) -> crate::errors::Result<()> {
    let wants_policy = profile == Profile::Image;
    // `[review]` of bridge.toml is read only when a flag is absent; no bridge.toml is the empty table.
    let review = if tripwires.is_none() || (wants_policy && settings_policy.is_none()) {
        let paths = Paths::resolve()?;
        let review = BridgeConfig::load(&paths)?.map(|c| c.review).unwrap_or_default();
        Some((review.tripwires_path(&paths), review.settings_policy_path(&paths)))
    } else {
        None
    };
    let rules = match (tripwires, &review) {
        (Some(p), _) => Rules::from_file(p),
        (None, Some((p, _))) => read_default_list(p).and_then(|t| match t {
            Some(text) => Rules::with_extras(&text, &p.display().to_string()),
            None => Ok(Rules::defaults()),
        }),
        (None, None) => Ok(Rules::defaults()),
    }
    .map_err(CliError::Msg)?;
    let policy = match (settings_policy, &review) {
        (Some(p), _) => read_list(p).and_then(|t| parse_policy(&t, &p.display().to_string())),
        (None, Some((_, p))) if wants_policy => read_default_list(p).and_then(|t| match t {
            Some(text) => parse_policy(&text, &p.display().to_string()),
            None => Ok(Vec::new()),
        }),
        (None, _) => Ok(Vec::new()),
    }
    .map_err(CliError::Msg)?;

    let (findings, files) = scan_dir(dir, profile, &rules, &policy).map_err(CliError::Msg)?;

    let mut hinted: Vec<(&str, &str)> = Vec::new();
    for f in &findings {
        let shim = f.file.rsplit('/').next() == Some("ai-env");
        if shim && is_tripwire(&f.rule) && !hinted.contains(&(f.file.as_str(), f.rule.as_str())) {
            hinted.push((f.file.as_str(), f.rule.as_str()));
            let fix = if f.rule.starts_with("tripwire:") {
                "narrow that line of the tripwires file"
            } else {
                "refine the built-in pattern in bridge::scan::DEFAULT_RULES (plan D7); never exempt the binary"
            };
            eprintln!("scan: hint: {} is the staged shim binary and trips {} by itself: {fix}", f.file, f.rule);
        }
    }

    // The verdict never depends on the printing: a reader that leaves early
    // (`ai-env infra scan DIR | head -1`) makes it a broken pipe, the
    // documented exit 0, which must not let findings through.
    let printed = print_report(dir, files, &findings, json);
    if findings.is_empty() {
        printed
    } else {
        Err(CliError::Policy(format!("{} finding(s) in {}", findings.len(), dir.display())))
    }
}

/// The stdout report of [`cmd_scan`]: the JSON document, or one line per finding and a summary.
fn print_report(dir: &Path, files: usize, findings: &[Finding], json: bool) -> crate::errors::Result<()> {
    if json {
        let report = Report { dir: dir.display().to_string(), clean: findings.is_empty(), files, findings };
        let text = serde_json::to_string_pretty(&report).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?;
        outln!("{text}");
    } else {
        for f in findings {
            outln!("{}:{}: {}", f.file, f.line, f.rule);
        }
        if findings.is_empty() {
            outln!("scan: clean ({files} files)");
        } else {
            outln!("scan: {} finding(s) ({files} files)", findings.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn p(src: &str) -> Pattern {
        Pattern::parse(src).unwrap_or_else(|e| panic!("{src:?}: {e}"))
    }

    /// Rule ids the built-ins report on `hay`.
    fn hits(hay: &str) -> Vec<String> {
        Rules::defaults().scan_bytes(hay.as_bytes()).into_iter().map(|(_, id)| id).collect()
    }

    fn rules_of(name: &str, json: &str, policy: &[&str]) -> Vec<(usize, &'static str)> {
        let policy: Vec<String> = policy.iter().map(|s| (*s).to_string()).collect();
        let mut v = settings_findings(name, json.as_bytes(), &policy);
        v.sort_unstable();
        v
    }

    // ---- matcher ----

    #[test]
    fn literal_finds_the_leftmost_offset() {
        assert_eq!(p("abc").find(b"xxabcabc"), Some(2));
        assert_eq!(p("abc").find(b"xxabxabd"), None);
        assert_eq!(p("abc").find(b""), None);
        assert_eq!(p("abc").find(b"ab"), None);
        assert_eq!(p("aab").find(b"aaab"), Some(1), "overlapping prefix candidates");
    }

    #[test]
    fn dot_is_any_byte_but_newline() {
        let d = p("a.c");
        assert_eq!(d.find(b"abc"), Some(0));
        assert_eq!(d.find(b"a\xffc"), Some(0));
        assert_eq!(d.find(b"a\x00c"), Some(0));
        assert_eq!(d.find(b"a\nc"), None);
    }

    #[test]
    fn classes_ranges_and_negation() {
        let c = p("x[abc]y");
        assert_eq!(c.find(b"xby"), Some(0));
        assert_eq!(c.find(b"xdy"), None);
        let r = p("[a-z0-9_-]+!");
        assert_eq!(r.find(b"  ab_9-!"), Some(2));
        assert_eq!(r.find(b"AB!"), None);
        assert_eq!(p("[-a]").find(b"x-"), Some(1), "leading '-' is literal");
        assert_eq!(p("[a-]").find(b"x-"), Some(1), "trailing '-' is literal");
        assert_eq!(p("[^-a]").find(b"-ab"), Some(2));
        assert_eq!(p("[.*+{]").find(b"ab{"), Some(2), "metacharacters are literal inside a class");
        assert_eq!(p("[a^]").find(b"x^"), Some(1), "'^' not first is literal");
        let n = p("<[^/ @]+>");
        assert_eq!(n.find(b"<ab> "), Some(0));
        assert_eq!(n.find(b"<a b>"), None);
        assert_eq!(n.find(b"<a/b>"), None);
        assert_eq!(p("a[^x]b").find(b"a\nb"), None, "a negated class never matches a newline");
    }

    #[test]
    fn star_plus_and_counts() {
        assert_eq!(p("ab*c").find(b"ac"), Some(0));
        assert_eq!(p("ab*c").find(b"xabbbc"), Some(1));
        assert_eq!(p("ab+c").find(b"ac"), None);
        assert_eq!(p("ab+c").find(b"abbc"), Some(0));
        assert_eq!(p("a{3}").find(b"aa"), None);
        assert_eq!(p("a{3}").find(b"baaa"), Some(1));
        assert_eq!(p("xa{2,}").find(b"xa xaa"), Some(3));
        assert_eq!(p("xa{2,}").find(b"xaaaaaaaaaaaa"), Some(0));
        assert_eq!(p("a{2,3}b").find(b"aaaab"), Some(1), "the leftmost start that reaches a match");
        assert_eq!(p("a{2,3}b").find(b"ab"), None);
        assert_eq!(p("x[0-9]{0,2}y").find(b"x123y xy"), Some(6));
        assert_eq!(p("x[0-9]{1000}").find(format!("x{}", "7".repeat(999)).as_bytes()), None);
        assert_eq!(p("x[0-9]{1000}").find(format!("x{}", "7".repeat(1000)).as_bytes()), Some(0));
        assert_eq!(p("ba{0}c").find(b"bc"), Some(0), "{{0}} drops its atom");
    }

    #[test]
    fn escapes_are_literal() {
        assert_eq!(p("a\\.b").find(b"axb a.b"), Some(4));
        assert_eq!(p("\\[x\\]").find(b"[x]"), Some(0));
        assert_eq!(p("\\\\").find(b"a\\b"), Some(1));
        assert_eq!(p("\\-\\{\\}\\*\\+\\(\\)\\|\\?\\^\\$\\.").find(b"-{}*+()|?^$."), Some(0));
        assert_eq!(p("[\\]\\-\\[]+z").find(b"a]-[z"), Some(1));
        assert_eq!(p("x\\ y").find(b"x y"), Some(0));
        assert_eq!(p("\\#x").find(b"#x"), Some(0));
    }

    #[test]
    fn matches_never_span_lines_and_are_reported_per_line() {
        let m = p("a.*b");
        assert_eq!(m.find(b"a\nb"), None);
        assert_eq!(m.find(b"a\nxab"), Some(3));
        assert_eq!(p("x.*y").find(b"..x..x..y"), Some(2), "greedy, yet the leftmost start");
        assert_eq!(p("ab").matching_lines(b"ab ab\n\nxx\nab\nab"), vec![1, 4, 5], "one entry per line");
        assert!(p("ab").matching_lines(b"").is_empty());
        assert_eq!(p("[a-z]+").matching_lines(b"1\n2a\n\n3"), vec![2]);
        assert_eq!(p("q").matching_lines(b"\n\n\nq\r\n"), vec![4]);
    }

    #[test]
    fn load_errors_name_the_construct_and_never_the_text() {
        let cases = [
            ("", "empty pattern"),
            ("(a)", "unsupported '('"),
            ("a)", "unsupported ')'"),
            ("a|b", "unsupported '|'"),
            ("ab?", "unsupported '?'"),
            ("^a", "unsupported '^'"),
            ("a$", "unsupported '$'"),
            ("[abc", "unbalanced '['"),
            ("a]", "unbalanced ']'"),
            ("a{2", "unbalanced '{'"),
            ("a}", "unbalanced '}'"),
            ("*a", "nothing to repeat"),
            ("+", "nothing to repeat"),
            ("{2}a", "nothing to repeat"),
            ("a**", "stacked quantifier"),
            ("a+{2}", "stacked quantifier"),
            ("a{3,2}", "min 3 above max 2"),
            ("a{1001}", "above 1000"),
            ("a{0,1001}", "above 1000"),
            ("a{}", "bad count"),
            ("a{,3}", "bad count"),
            ("a{1,2,3}", "bad count"),
            ("a{x}", "bad count"),
            ("\\d", "unsupported escape"),
            ("a\\n", "unsupported escape"),
            ("[\\w]", "unsupported escape"),
            ("a\\", "trailing backslash"),
            ("[]", "empty class"),
            ("[^]", "empty class"),
            ("[z-a]", "reversed range"),
            ("[a-c-e]", "ambiguous '-'"),
            ("[[:alpha:]]", "unescaped '['"),
            ("a\nb", "newline"),
            ("\u{e9}+", "non-ASCII"),
            ("[\u{e9}]", "non-ASCII"),
            ("a*", "empty string"),
            ("a{0}", "empty string"),
            ("[a-z]*.*", "empty string"),
        ];
        for (src, want) in cases {
            let e = Pattern::parse(src).unwrap_err();
            assert!(e.contains(want), "{src:?}: {e}");
        }
        let overflow = format!("a{{{}}}", "9".repeat(23));
        assert!(Pattern::parse(&overflow).unwrap_err().contains("above 1000"), "a count that overflows usize");
        let e = Pattern::parse("canaryword(x").unwrap_err();
        assert_eq!(e, "unsupported '(' at column 11 (no groups, alternation, '?' or anchors; escape it with \\)");
        assert_eq!(format!("{:?}", p("canaryword[0-9]")), "Pattern { prefix: 10 bytes, atoms: 1 }", "Debug shows sizes only");
    }

    // ---- rules ----

    #[test]
    fn built_ins_are_the_plan_table_and_all_have_a_literal_prefix() {
        let ids: Vec<&str> = DEFAULT_RULES.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, ["anthropic-key", "aws-access-key-id", "private-key-block", "age-identity", "mysql-pwd", "github-pat", "slack-token", "jwt", "url-credentials"]);
        assert_eq!(DEFAULT_RULES[0].1, "sk-ant-[a-z]{2,8}[0-9]{2}-[A-Za-z0-9_-]{20}");
        assert_eq!(DEFAULT_RULES[2].1, "-----BEGIN .*PRIVATE\\ KEY", "§10 text with an escaped space");
        assert_eq!(DEFAULT_RULES[4].1, "MYSQL_PWD\\=", "§10 text with an escaped '='");
        assert_eq!(DEFAULT_RULES[7].1, "eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20}", "deviation from §10: see DEFAULT_RULES");
        assert_eq!(DEFAULT_RULES[8].1, "://[^/ @:]+:[^/ @]+@");
        for (id, src) in DEFAULT_RULES {
            assert!(!p(src).prefix.is_empty(), "{id} needs a literal prefix for the fast path");
        }
        assert_eq!(Rules::defaults().ids().collect::<Vec<_>>(), ids);
    }

    /// One or more runtime-built positives per built-in rule.
    fn positives() -> Vec<(&'static str, String)> {
        let sep = "://";
        let dashes = "-".repeat(5);
        vec![
            ("anthropic-key", format!("{}oat01-{}", "sk-ant-", "Q".repeat(20))),
            ("anthropic-key", format!("{}api03-{}", "sk-ant-", "a_-9".repeat(5))),
            ("aws-access-key-id", format!("{}{}", "AKIA", "Q7".repeat(8))),
            ("private-key-block", format!("{dashes}BEGIN OPENSSH PRIVATE KEY{dashes}")),
            ("private-key-block", format!("{dashes}BEGIN PRIVATE KEY{dashes}")),
            ("age-identity", format!("{}{}", "AGE-SECRET-KEY-1", "Q".repeat(20))),
            ("mysql-pwd", format!("export {}_PWD=x", "MYSQL")),
            ("github-pat", format!("{}{}", "ghp_", "q".repeat(20))),
            ("slack-token", format!("{}{}", "xoxb-", "1".repeat(10))),
            ("slack-token", format!("{}{}", "xoxp-", "a-".repeat(5))),
            ("jwt", format!("{}{}.{}", "eyJ", "a".repeat(20), "b".repeat(20))),
            // The shape of a standard HS256 token: 33 header characters after `eyJ`.
            ("jwt", format!("{}{}.{}{}.{}", "eyJ", "h".repeat(33), "eyJ", "p".repeat(60), "s".repeat(43))),
            ("url-credentials", format!("postgres{sep}{}:{}@db", "user", "pw")),
        ]
    }

    #[test]
    fn each_built_in_matches_a_runtime_built_positive() {
        let cases = positives();
        for (id, _) in DEFAULT_RULES {
            assert!(cases.iter().any(|(c, _)| *c == id), "{id} has no positive");
        }
        for (id, positive) in &cases {
            let hay = format!("before\n  {positive} after\n");
            assert_eq!(hits(&hay), vec![(*id).to_string()], "{id}");
            assert_eq!(Rules::defaults().scan_bytes(hay.as_bytes())[0].0, 2, "{id} reports the line");
        }
    }

    /// The compiled binary carries every built-in pattern verbatim (alone and
    /// packed side by side in read-only data): that text must trip no
    /// built-in, while the positives still do.
    #[test]
    fn built_in_pattern_text_trips_no_built_in() {
        for (id, src) in DEFAULT_RULES {
            assert!(hits(src).is_empty(), "the text of {id} trips {:?}", hits(src));
        }
        let packed: String = DEFAULT_RULES.iter().map(|(_, src)| *src).collect();
        assert!(hits(&packed).is_empty(), "the packed texts trip {:?}", hits(&packed));
        for (id, positive) in positives() {
            assert_eq!(hits(&positive), vec![id.to_string()], "{id}");
        }
    }

    #[test]
    #[should_panic(expected = "built-in tripwire broken-rule: unsupported '(' at column 2")]
    fn a_built_in_that_does_not_parse_names_its_rule_id() {
        let _ = compile_built_ins(&[("anthropic-key", DEFAULT_RULES[0].1), ("broken-rule", "a(b")]);
    }

    #[test]
    fn built_ins_miss_their_near_misses() {
        let sep = "://";
        let dashes = "-".repeat(5);
        let misses = [
            "sk-ant-".to_string(),
            format!("{}oat01-{}", "sk-ant-", "Q".repeat(19)),
            format!("{}OAT01-{}", "sk-ant-", "Q".repeat(20)),
            format!("{}oat1-{}", "sk-ant-", "Q".repeat(20)),
            format!("{}[redacted:len=40]", "sk-ant-"),
            format!("{}{}", "AKIA", "Q".repeat(15)),
            format!("{}{}", "AKIA", "q".repeat(16)),
            format!("{dashes}BEGIN PUBLIC KEY{dashes}"),
            format!("{dashes}BEGIN RSA\nPRIVATE KEY"),
            format!("{}BEGIN PRIVATE KEY", "-".repeat(4)),
            format!("{}{}", "AGE-SECRET-KEY-1", "Q".repeat(19)),
            format!("{}{}", "AGE-SECRET-KEY-1", "q".repeat(20)),
            format!("{}{}", "AGE-SECRET-KEY-1", "GETTRACEPUTPATCHOPTIONS"),
            format!("{}{}", "AGE-SECRET-KEY-1", "B".repeat(20)),
            format!("{}_PWD", "MYSQL"),
            format!("{}_PWD =x", "MYSQL"),
            format!("{}{}", "ghp_", "q".repeat(19)),
            format!("{}{}", "ghp-", "q".repeat(20)),
            format!("{}{}", "xoxa-", "1".repeat(10)),
            format!("{}{}", "xoxb-", "1".repeat(9)),
            format!("{}{}.{}", "eyJ", "a".repeat(19), "b".repeat(20)),
            format!("{}{}{}", "eyJ", "a".repeat(20), "b".repeat(20)),
            format!("{}{}.{}", "eyJ", "a".repeat(20), "b".repeat(19)),
            format!("https{sep}example.com/path"),
            format!("https{sep}user@example.com"),
            format!("https{sep}a:b/c@d"),
            format!("https{sep}a :b@d"),
        ];
        for m in &misses {
            assert!(hits(m).is_empty(), "near-miss {m:?} tripped {:?}", hits(m));
        }
    }

    #[test]
    fn extras_add_rules_named_by_line_and_errors_name_file_and_line() {
        let r = Rules::with_extras("# comment\n\n  INTERNAL-[0-9]{4}  \nplain\n", "/x/t.txt").unwrap();
        let ids: Vec<&str> = r.ids().collect();
        assert_eq!(ids.len(), 11);
        assert_eq!(&ids[9..], ["tripwire:3", "tripwire:4"]);
        assert_eq!(r.scan_bytes(b"a\nINTERNAL-1234\nplain"), vec![(2, "tripwire:3".to_string()), (3, "tripwire:4".to_string())]);
        let e = Rules::with_extras("ok\n\n(canaryword\n", "/x/t.txt").unwrap_err();
        assert!(e.starts_with("/x/t.txt:3: unsupported '(' at column 1"), "{e}");
        assert!(!e.contains("canaryword"), "a load error never echoes the pattern: {e}");
        assert!(Rules::from_file(Path::new("/nonexistent/ai-env-scan/t.txt")).unwrap_err().starts_with("cannot read /nonexistent/ai-env-scan/t.txt"));
    }

    #[test]
    fn policy_lines_are_allow_entries() {
        assert_eq!(parse_policy("# c\n\nallow Bash(ls:*)\n  allow   Read(~/x)  \n", "p").unwrap(), ["Bash(ls:*)", "Read(~/x)"]);
        assert_eq!(parse_policy("allow a\nalow canaryword\n", "/p.txt").unwrap_err(), "/p.txt:2: expected `allow <entry>`");
        assert!(parse_policy("allow \n", "p").is_err());
    }

    /// 4 MiB of xorshift noise, with candidate prefixes planted so the
    /// per-line pass runs too, scanned with every built-in: well under a
    /// second even in a debug build.
    #[test]
    fn four_mib_of_noise_scans_fast_with_every_default() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut buf: Vec<u8> = (0..4usize << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[3]
            })
            .collect();
        let mut next = |bound: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            usize::try_from(x % bound as u64).unwrap()
        };
        // Bare prefixes everywhere, so the per-line pass runs on many lines ...
        let bare = [format!("{}BEGIN ", "-".repeat(5)), "://".into(), "eyJ".into(), "xoxb-".into(), "sk-ant-".into(), "AKIA".into()];
        for pre in bare.iter().cycle().take(6000) {
            let at = next(buf.len() - 16);
            buf[at..at + pre.len()].copy_from_slice(pre.as_bytes());
        }
        // ... and one real positive per rule, each on a line of its own.
        let cases = positives();
        for (k, (_, positive)) in cases.iter().enumerate() {
            let line = format!("\n{positive}\n");
            let at = 100_000 + k * 300_000;
            buf[at..at + line.len()].copy_from_slice(line.as_bytes());
        }
        let rules = Rules::defaults();
        let t0 = Instant::now();
        let found = rules.scan_bytes(&buf);
        let took = t0.elapsed();
        eprintln!("4 MiB of noise, every default: {took:?} ({} hits)", found.len());
        assert!(took < Duration::from_secs(1), "4 MiB took {took:?} ({} hits)", found.len());
        for (id, _) in DEFAULT_RULES {
            let planted = cases.iter().filter(|(c, _)| *c == id).count();
            assert!(found.iter().filter(|(_, r)| r == id).count() >= planted, "{id}: planted {planted}, found {found:?}");
        }
    }

    #[test]
    fn no_pattern_backtracks_on_a_long_line() {
        let line = vec![b'a'; 256 << 10];
        let t0 = Instant::now();
        for src in ["a*a*a*a*b", "a.*b", "a{1,1000}b", "[a-z]+[a-z]+[a-z]+!", "a{1000}b"] {
            assert_eq!(p(src).find(&line), None, "{src}");
        }
        let took = t0.elapsed();
        eprintln!("256 KiB line, five patterns: {took:?}");
        assert!(took < Duration::from_secs(1), "256 KiB line took {took:?}");
    }

    /// A line that keeps every stage busy to its end (a prefix occurrence at
    /// every byte, so the bounded atom's window stays full): the scratch is
    /// bounded by the counts, where the per-line arrays this replaced took 16
    /// bytes per byte of line.
    #[test]
    fn a_long_line_needs_scratch_bounded_by_the_counts_not_the_line() {
        let pat = p("z[a-z]{1,1000}[a-z]{1000,}[0-9]");
        let mut line = vec![b'z'; 2 << 20];
        let mut stages = Vec::new();
        assert_eq!(pat.leftmost_with(&line, &mut stages), None);
        let held: usize = stages.iter().map(|s| s.queue.capacity()).sum();
        assert!(stages[0].queue.capacity() >= 1000, "the input keeps the window full ({})", stages[0].queue.capacity());
        assert!(held <= 4 << 10, "{held} scratch entries for a 2 MiB line");
        line.push(b'7');
        assert_eq!(pat.find(&line), Some(0), "the leftmost start, found at the far end");
    }

    /// The review's shape: one 16 MiB line that starts with a prefix hit
    /// (`eyJ`) and stays inside the next atom's class to its end, scanned with
    /// every default. Linear time, and no scratch in proportion to the line.
    #[test]
    fn a_sixteen_mib_line_after_a_prefix_hit_scans_with_every_default() {
        let mut line = b"eyJ".to_vec();
        line.resize(16 << 20, b'a');
        let rules = Rules::defaults();
        let t0 = Instant::now();
        assert!(rules.scan_bytes(&line).is_empty());
        let took = t0.elapsed();
        eprintln!("16 MiB line after a prefix hit, every default: {took:?}");
        assert!(took < Duration::from_secs(20), "16 MiB line took {took:?}");
        let jwt = rules.rules.iter().find(|r| r.id == "jwt").unwrap();
        let mut stages = Vec::new();
        assert_eq!(jwt.pattern.leftmost_with(&line, &mut stages), None);
        assert!(stages.iter().all(|s| s.queue.capacity() <= 64), "jwt scratch grew with the line");
    }

    /// Brute force by the definition: the leftmost start from which the atoms
    /// (prefix bytes first) match some `hay[start..end]`.
    fn reference(pat: &Pattern, hay: &[u8]) -> Option<usize> {
        let mut atoms: Vec<Atom> = pat
            .prefix
            .iter()
            .map(|b| {
                let mut set = ByteSet::EMPTY;
                set.add(*b);
                Atom { set, min: 1, max: 1 }
            })
            .collect();
        atoms.extend(pat.rest.iter().cloned());
        (0..=hay.len()).find(|&start| {
            let mut ends = vec![start];
            for a in &atoms {
                let mut next = Vec::new();
                for &from in &ends {
                    let mut q = from;
                    loop {
                        if q - from >= a.min {
                            next.push(q);
                        }
                        if q - from == a.max || q == hay.len() || !a.set.has(hay[q]) {
                            break;
                        }
                        q += 1;
                    }
                }
                next.sort_unstable();
                next.dedup();
                ends = next;
            }
            !ends.is_empty()
        })
    }

    /// The single pass (with its jumps and early stop) agrees with the
    /// definition on thousands of small random patterns and multi-line inputs.
    #[test]
    fn the_single_pass_agrees_with_a_brute_force_reference() {
        let atoms = ["a", "b", "x", ".", "[ab]", "[^a]", "\\."];
        let quants = ["", "", "*", "+", "{2}", "{1,3}", "{2,}", "{0,2}"];
        let alphabet = b"abx.\n";
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |bound: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            usize::try_from(x % bound as u64).unwrap()
        };
        let mut checked = 0;
        for _ in 0..6000 {
            let n = 1 + next(4);
            let mut src = String::new();
            for _ in 0..n {
                src.push_str(atoms[next(atoms.len())]);
                src.push_str(quants[next(quants.len())]);
            }
            let Ok(pat) = Pattern::parse(&src) else { continue };
            let len = next(28);
            let hay: Vec<u8> = (0..len).map(|_| alphabet[next(alphabet.len())]).collect();
            assert_eq!(pat.find(&hay), reference(&pat, &hay), "{src:?} on {:?}", String::from_utf8_lossy(&hay));
            checked += 1;
        }
        assert!(checked > 4000, "only {checked} patterns parsed");
    }

    // ---- settings rules ----

    const BYPASS_DOC: &str = "{\n  \"permissions\": {\n    \"defaultMode\": \"bypassPermissions\",\n    \"allow\": []\n  }\n}\n";

    /// A managed-settings document without any D6 key: the four
    /// `managed-hardening` findings at line 0, then `rest`.
    fn unhardened(rest: &[(usize, &'static str)]) -> Vec<(usize, &'static str)> {
        // Findings are reported sorted by line, then rule id.
        let mut v: Vec<(usize, &'static str)> = MANAGED_RULES.iter().map(|r| (0, *r)).collect();
        v.sort_unstable();
        v.extend_from_slice(rest);
        v
    }

    /// The D6 managed settings, one key per line (the hardened values sit on lines 3, 4, 7 and 8).
    const HARDENED: &str = "{\n\"permissions\": {\n\"disableBypassPermissionsMode\": \"disable\",\n\"disableAutoMode\": \"disable\"\n},\n\"env\": {\n\"DISABLE_AUTOUPDATER\": \"1\",\n\"DISABLE_UPDATES\": \"1\"\n}\n}\n";

    #[test]
    fn managed_settings_must_carry_the_d6_values() {
        assert!(rules_of("managed-settings.json", HARDENED, &[]).is_empty());
        let repo = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/managed-settings.json")).unwrap();
        assert!(settings_findings("managed-settings.json", &repo, &[]).is_empty(), "the committed image/managed-settings.json");
        // A weakened value is named at its key's line.
        let weak = HARDENED.replace("\"disableBypassPermissionsMode\": \"disable\"", "\"disableBypassPermissionsMode\": \"enable\"");
        assert_eq!(rules_of("managed-settings.json", &weak, &[]), vec![(3, "managed-hardening:permissions.disableBypassPermissionsMode")]);
        let number = HARDENED.replace("\"DISABLE_UPDATES\": \"1\"", "\"DISABLE_UPDATES\": 1");
        assert_eq!(rules_of("managed-settings.json", &number, &[]), vec![(8, "managed-hardening:env.DISABLE_UPDATES")], "the number 1 is not the string \"1\"");
        // A dropped key has no line of its own: the file as a whole.
        let dropped = HARDENED.replace(",\n\"disableAutoMode\": \"disable\"", "");
        assert_eq!(rules_of("managed-settings.json", &dropped, &[]), vec![(0, "managed-hardening:permissions.disableAutoMode")]);
        let no_env = HARDENED.replace("\"DISABLE_AUTOUPDATER\": \"1\",\n\"DISABLE_UPDATES\": \"1\"", "");
        assert_eq!(rules_of("managed-settings.json", &no_env, &[]), vec![(0, "managed-hardening:env.DISABLE_AUTOUPDATER"), (0, "managed-hardening:env.DISABLE_UPDATES")]);
        // The rule ids follow the shared list exactly.
        for ((path, _), rule) in MANAGED_HARDENING.iter().zip(MANAGED_RULES) {
            assert_eq!(rule, format!("managed-hardening:{}", path.join(".")));
        }
        assert_eq!(rules_of("managed-settings.json", "{}", &[]), unhardened(&[]));
        assert_eq!(rules_of("managed-settings.json", "{\"permissions\": {}, \"env\": {}}", &[]), unhardened(&[]));
        // Only managed settings carry the D6 values.
        assert!(rules_of("settings.json", "{}", &[]).is_empty());
    }

    #[test]
    fn claude_json_bakes_no_project_entry() {
        assert!(rules_of("claude.json", "{\"hasCompletedOnboarding\":true,\"projects\":{}}", &[]).is_empty());
        assert_eq!(rules_of("claude.json", "{\"projects\": {\n\"/w\": {}}}", &[]), vec![(2, "project-entry")]);
        // The review's example: a trusted project with a broad allow list and
        // an MCP server whose env names a password, none of which the
        // settings rules see; one finding per entry, at its key.
        let example = format!(
            "{{\"hasCompletedOnboarding\":true,\"projects\":{{\n\"/Users/mike/work\":{{\"hasTrustDialogAccepted\":true,\"allowedTools\":[\"Bash(*)\"],\"mcpServers\":{{\"db\":{{\"command\":\"sh\",\"env\":{{\"DB_{}\":\"{}\"}}}}}}}},\n\"/Users/mike/other\": {{}}}}}}",
            "PASSWORD",
            "x".repeat(8)
        );
        assert_eq!(rules_of(".claude.json", &example, &[]), vec![(2, "project-entry"), (3, "project-entry")]);
    }

    #[test]
    fn image_settings_and_the_d6_managed_settings_are_clean() {
        assert!(rules_of("settings.json", r#"{"permissions":{"defaultMode":"default","allow":[]}}"#, &[]).is_empty());
        let managed = r#"{"permissions":{"disableBypassPermissionsMode":"disable","disableAutoMode":"disable"},"env":{"DISABLE_AUTOUPDATER":"1","DISABLE_UPDATES":"1"}}"#;
        assert!(rules_of("managed-settings.json", managed, &[]).is_empty());
        assert!(rules_of("claude.json", r#"{"hasCompletedOnboarding":true}"#, &[]).is_empty());
        assert!(rules_of(".claude.json", r#"{"hasCompletedOnboarding":true,"projects":{}}"#, &[]).is_empty());
        let full = r#"{"$schema":"https://json.schemastore.org/claude-code-settings.json","permissions":{"defaultMode":"plan","allow":[],"deny":["Bash(rm:*)"],"ask":[],"additionalDirectories":[]},"env":{"LANG":"C.UTF-8"},"model":"opus","includeCoAuthoredBy":false,"cleanupPeriodDays":30}"#;
        assert!(rules_of("settings.local.json", full, &[]).is_empty());
    }

    #[test]
    fn other_file_names_get_no_settings_rules() {
        assert!(rules_of("config.json", "not json", &[]).is_empty());
        assert!(rules_of("settings.json.bak", "[]", &[]).is_empty());
    }

    #[test]
    fn not_json_object_whole_file_or_member() {
        assert_eq!(rules_of("settings.json", "[1]", &[]), vec![(0, "not-json-object")]);
        assert_eq!(rules_of("settings.json", "\"text\"", &[]), vec![(0, "not-json-object")]);
        assert_eq!(rules_of("managed-settings.json", "{\n  \"env\": {\n    oops\n}", &[]), vec![(3, "not-json-object")], "a syntax error carries the parser's line");
        assert_eq!(rules_of(".claude.json", "", &[]), vec![(1, "not-json-object")]);
        assert_eq!(settings_findings("settings.json", b"{\"model\": \"\xff\"}", &[]), vec![(1, "not-json-object")], "not UTF-8");
        assert_eq!(rules_of("settings.json", "{\"permissions\": [],\n\"env\": \"x\"}", &[]), vec![(1, "not-json-object"), (2, "not-json-object")]);
        assert_eq!(rules_of("claude.json", "{\n\"projects\": []\n}", &[]), vec![(2, "not-json-object")]);
    }

    #[test]
    fn default_mode_and_bypass_name_the_key_line() {
        assert_eq!(rules_of("settings.json", BYPASS_DOC, &[]), vec![(3, "bypass-permissions"), (3, "default-mode")]);
        assert_eq!(rules_of("settings.json", r#"{"permissions":{"defaultMode":"acceptEdits"}}"#, &[]), vec![(1, "default-mode")]);
        assert_eq!(rules_of("settings.json", r#"{"permissions":{"defaultMode":1}}"#, &[]), vec![(1, "default-mode")]);
        assert!(rules_of("settings.json", r#"{"permissions":{"defaultMode":"plan"}}"#, &[]).is_empty());
        // Anywhere, as a string VALUE: nested, in an array, in a config file.
        assert_eq!(rules_of("settings.json", "{\"env\": {\"MODE\": \"x\"},\n\"permissions\": {\"deny\": [\"a\",\n \"bypassPermissions\"]}}", &[]), vec![(3, "bypass-permissions")]);
        assert_eq!(rules_of("claude.json", "{\"projects\": {\"/w\": {\n\"mode\": \"bypassPermissions\"}}}", &[]), vec![(1, "project-entry"), (2, "bypass-permissions")]);
        // A key of that name is not a value (it is an unexpected key).
        assert_eq!(rules_of("settings.json", "{\"bypassPermissions\": true}", &[]), vec![(1, "unexpected-key")]);
        // An escaped spelling decodes to the same value and is still located.
        assert_eq!(rules_of("settings.json", "{\"env\":\n{\"X\": \"bypass\\u0050ermissions\"}}", &[]), vec![(2, "bypass-permissions")]);
        // A shadowed duplicate still counts: the bytes carry the value.
        assert_eq!(rules_of("settings.json", "{\"permissions\": {\"defaultMode\": \"bypassPermissions\",\n\"defaultMode\": \"default\"}}", &[]), vec![(1, "bypass-permissions")]);
    }

    #[test]
    fn broad_allow_is_refused_even_when_the_policy_lists_it() {
        for entry in BROAD_ALLOW {
            let doc = format!("{{\"permissions\": {{\"allow\": [\n{}\n]}}}}", serde_json::to_string(entry).unwrap());
            assert_eq!(rules_of("settings.json", &doc, &[entry]), vec![(2, "broad-allow")], "{entry}");
        }
    }

    #[test]
    fn allow_entries_must_be_in_the_policy() {
        let doc = "{\"permissions\": {\"allow\": [\n\"Bash(ls:*)\",\n\"Read(~/x)\"\n]}}";
        assert_eq!(rules_of("settings.json", doc, &[]), vec![(2, "allow-not-in-policy"), (3, "allow-not-in-policy")]);
        assert_eq!(rules_of("settings.json", doc, &["Bash(ls:*)"]), vec![(3, "allow-not-in-policy")]);
        assert!(rules_of("settings.json", doc, &["Bash(ls:*)", "Read(~/x)"]).is_empty());
        assert_eq!(rules_of("settings.json", "{\"permissions\": {\"allow\":\n \"Bash(ls:*)\"}}", &["Bash(ls:*)"]), vec![(1, "allow-not-in-policy")], "allow must be an array");
        assert_eq!(rules_of("managed-settings.json", "{\"permissions\": {\"allow\": [\n7]}}", &[]), unhardened(&[(1, "allow-not-in-policy")]), "a non-string entry falls back to the key's line");
    }

    #[test]
    fn unexpected_keys_per_file_kind() {
        let doc = "{\n\"model\": \"x\",\n\"hooks\": {},\n\"permissions\": {\n\"defaultMode\": \"default\",\n\"bypass\": 1\n}\n}";
        assert_eq!(rules_of("settings.json", doc, &[]), vec![(3, "unexpected-key"), (6, "unexpected-key")]);
        assert_eq!(rules_of("managed-settings.json", doc, &[]), unhardened(&[(2, "unexpected-key"), (3, "unexpected-key"), (6, "unexpected-key")]));
        assert_eq!(rules_of(".claude.json", "{\n\"hasCompletedOnboarding\": true,\n\"userID\": \"u\"\n}", &[]), vec![(3, "unexpected-key")]);
    }

    #[test]
    fn secret_looking_env_names_are_refused() {
        let doc = "{\"env\": {\n\"GITHUB_TOKEN\": \"x\",\n\"api_key\": \"x\",\n\"DB_PASSWORD\": \"x\",\n\"OAUTH_X\": \"x\",\n\"MY_CREDENTIALS\": \"x\",\n\"Secret\": \"x\",\n\"DISABLE_AUTOUPDATER\": \"1\",\n\"LANG\": \"C\"\n}}";
        assert_eq!(rules_of("settings.json", doc, &[]), (2..=7).map(|l| (l, "secret-env-name")).collect::<Vec<_>>());
    }

    // ---- walk ----

    #[test]
    fn scan_dir_reports_sorted_relative_paths_symlinks_and_special_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("b/c")).unwrap();
        std::fs::write(root.join("a.txt"), "plain\n").unwrap();
        std::fs::write(root.join("b/c/key.pem"), format!("x\n{}BEGIN EC PRIVATE KEY{}\n", "-".repeat(5), "-".repeat(5))).unwrap();
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("b/link")).unwrap();
        let _sock = std::os::unix::net::UnixListener::bind(root.join("sock")).unwrap();
        let (findings, files) = scan_dir(root, Profile::Repo, &Rules::defaults(), &[]).unwrap();
        let got: Vec<String> = findings.iter().map(|f| format!("{}:{}: {}", f.file, f.line, f.rule)).collect();
        assert_eq!(got, ["b/c/key.pem:2: private-key-block", "b/link:0: symlink", "sock:0: special-file"]);
        assert_eq!(files, 2);
    }

    /// The walk re-checks every node when it opens it: what the `lstat` saw
    /// but is gone by the open (a symlink or another directory in the place
    /// of a directory, a symlink in the place of a file) is reported as
    /// `symlink`, and nothing below it is read. The swaps are staged by
    /// handing `subdir` and `file` a stale `lstat`, so no race is needed.
    #[test]
    fn a_node_swapped_since_its_lstat_is_reported_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("real")).unwrap();
        std::fs::create_dir(root.join("other")).unwrap();
        std::fs::write(root.join("real/t.txt"), format!("{}oat01-{}\n", "sk-ant-", "Q".repeat(20))).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("dlink")).unwrap();
        std::os::unix::fs::symlink(root.join("real/t.txt"), root.join("flink")).unwrap();
        let fd = std::fs::File::open(root).unwrap();
        let dir = fd.as_fd();
        let real = stat_at(dir, c"real").unwrap();
        let other = stat_at(dir, c"other").unwrap();
        let rules = Rules::defaults();
        let mut walk = Walk { profile: Profile::Repo, rules: &rules, policy: &[], findings: Vec::new(), files: 0 };
        // The lstat saw the directory `real`; the open finds a symlink (O_NOFOLLOW refuses it).
        walk.subdir(dir, c"dlink", &real, &root.join("dlink"), "dlink").unwrap();
        // The lstat saw `other`; the open finds `real`, a different node (device, inode).
        walk.subdir(dir, c"real", &other, &root.join("real"), "real").unwrap();
        // The lstat saw a regular file; the open finds a symlink (ELOOP).
        walk.file(dir, c"flink", &root.join("flink"), "flink").unwrap();
        let got: Vec<String> = walk.findings.iter().map(|f| format!("{}:{}: {}", f.file, f.line, f.rule)).collect();
        assert_eq!(got, ["dlink:0: symlink", "real:0: symlink", "flink:0: symlink"]);
        assert_eq!(walk.files, 0, "nothing was read through a swapped node");
        // Unchanged since its lstat, the same directory is entered.
        walk.subdir(dir, c"real", &real, &root.join("real"), "real").unwrap();
        assert_eq!(walk.findings.last(), Some(&Finding { file: "real/t.txt".into(), line: 1, rule: "anthropic-key".into() }));
        assert_eq!(walk.files, 1);
    }

    #[test]
    fn scan_dir_applies_settings_rules_only_in_the_image_profile() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("claude")).unwrap();
        std::fs::write(tmp.path().join("claude/settings.json"), BYPASS_DOC).unwrap();
        let (repo, _) = scan_dir(tmp.path(), Profile::Repo, &Rules::defaults(), &[]).unwrap();
        assert!(repo.is_empty());
        let (image, files) = scan_dir(tmp.path(), Profile::Image, &Rules::defaults(), &[]).unwrap();
        let rules: Vec<&str> = image.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(rules, ["bypass-permissions", "default-mode"]);
        assert!(image.iter().all(|f| f.file == "claude/settings.json" && f.line == 3));
        assert_eq!(files, 1);
    }

    #[test]
    fn scan_dir_refuses_a_missing_dir_or_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let e = scan_dir(&tmp.path().join("nope"), Profile::Image, &Rules::defaults(), &[]).unwrap_err();
        assert!(e.starts_with("cannot scan "), "{e}");
        std::fs::write(tmp.path().join("f"), "x").unwrap();
        let e = scan_dir(&tmp.path().join("f"), Profile::Image, &Rules::defaults(), &[]).unwrap_err();
        assert!(e.ends_with("not a directory"), "{e}");
    }
}
