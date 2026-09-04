//! The edit form: a key/value list where names, comments and layout are
//! plaintext and every VALUE is a sealed cell — at most one revealed at a
//! time, into the mlocked scratch. State machine and rendering are separate
//! so the machine is testable without a terminal.
//!
//! Input-safety invariants (audit v4.1):
//! * modified keys never trigger Browse commands (Ctrl+C is a quit request,
//!   everything else modified is ignored);
//! * pastes are only accepted while editing a value/text, are rejected whole
//!   if they contain newlines, and are ignored in Browse/Confirm modes;
//! * a seal/commit failure is a STATUS, never a session-fatal error;
//! * read-only sessions can reveal and navigate but not mutate.
use super::cells::{Prekey, SealedCell, SealedRing};
use super::scratch::Scratch;
use crate::dotenv::{is_valid_name, validate_raw_value, RawFile, RawLine};
use crate::errors::Result;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as UiLine, Span};
use ratatui::Frame;
use std::time::{Duration, Instant};

pub const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";
pub const IDLE_RESEAL: Duration = Duration::from_secs(30);
const UNDO_DEPTH: usize = 32;
const PAGE_JUMP: usize = 10;

// ---- document ---------------------------------------------------------------

pub struct EntryRow {
    pub before_eq: String,
    pub name: String,
    pub cell: SealedCell,
    pub undo: SealedRing,
    pub crlf: bool,
}

pub enum Row {
    Comment { text: String, crlf: bool },
    Blank { text: String, crlf: bool },
    Entry(EntryRow),
}

impl Row {
    #[must_use]
    pub fn crlf(&self) -> bool {
        match self {
            Row::Comment { crlf, .. } | Row::Blank { crlf, .. } => *crlf,
            Row::Entry(e) => e.crlf,
        }
    }
}

pub struct Document {
    pub rows: Vec<Row>,
    pub trailing_newline: bool,
    next_gen: u64,
}

impl Document {
    /// Seal every value of a parsed file. The plaintext values inside
    /// `raw` are Zeroizing and wiped when this returns. Seal errors name the
    /// offending variable and line (they surface AFTER the Touch ID prompt,
    /// so they must be actionable).
    pub fn seal_from(raw: RawFile, prekey: &Prekey) -> Result<Self> {
        let mut doc = Document {
            rows: Vec::with_capacity(raw.lines.len()),
            trailing_newline: raw.trailing_newline,
            next_gen: 0,
        };
        for (idx, line) in raw.lines.into_iter().enumerate() {
            let row = match line {
                RawLine::Comment { text, crlf } => Row::Comment { text, crlf },
                RawLine::Blank { text, crlf } => Row::Blank { text, crlf },
                RawLine::Entry { before_eq, name, value, crlf } => {
                    let generation = doc.bump_gen();
                    let cell = SealedCell::seal(prekey, &name, generation, value.as_bytes())
                        .map_err(|e| {
                            crate::errors::CliError::Msg(format!(
                                "cannot open for editing — value of {name:?} (line {}): {e}. \
                                 Split the value, or repair via: ai-env decrypt --force",
                                idx + 1
                            ))
                        })?;
                    Row::Entry(EntryRow {
                        before_eq,
                        name,
                        cell,
                        undo: SealedRing::new(UNDO_DEPTH),
                        crlf,
                    })
                }
            };
            doc.rows.push(row);
        }
        Ok(doc)
    }

    pub fn bump_gen(&mut self) -> u64 {
        self.next_gen += 1;
        self.next_gen
    }

    fn has_other_entry_named(&self, name: &str, except_row: usize) -> bool {
        self.rows.iter().enumerate().any(|(i, r)| {
            i != except_row && matches!(r, Row::Entry(e) if e.name == name)
        })
    }
}

// ---- state machine ----------------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum TextKind {
    /// Editing an EXISTING comment row in place.
    Comment,
    /// Renaming an existing entry.
    Rename,
    /// A NEW entry: nothing is inserted until Enter (rendered as a virtual row).
    NewEntryName,
    /// A NEW comment: nothing is inserted until Enter (rendered as a virtual row).
    NewComment,
}

impl TextKind {
    #[must_use]
    pub fn is_virtual(self) -> bool {
        matches!(self, TextKind::NewEntryName | TextKind::NewComment)
    }
}

pub enum Mode {
    Browse,
    /// The selected entry's value is unsealed in the scratch.
    EditValue { row: usize, cursor: usize },
    /// Editing a plaintext element in an ordinary String. For virtual kinds,
    /// `row` is the INSERTION index (no row exists there yet).
    EditText { row: usize, kind: TextKind, buf: String, cursor: usize },
    ConfirmDelete(usize),
    ConfirmQuit,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Action {
    Continue,
    Save,
    Quit,
}

pub struct FormState {
    pub doc: Document,
    pub sel: usize,
    pub mode: Mode,
    pub dirty: bool,
    pub read_only: bool,
    pub status: String,
    pub file_name: String,
    pub last_activity: Instant,
    pub scroll: usize,
}

impl FormState {
    pub fn new(doc: Document, file_name: String, read_only: bool) -> Self {
        Self {
            doc,
            sel: 0,
            mode: Mode::Browse,
            dirty: false,
            read_only,
            status: String::new(),
            file_name,
            last_activity: Instant::now(),
            scroll: 0,
        }
    }

    fn set_status(&mut self, s: impl Into<String>) {
        self.status = s.into();
    }

    /// Commit the scratch into the given entry's cell (seal, push undo).
    /// NEVER session-fatal: validation and seal failures return Ok(false)
    /// with a status (audit fix 11b).
    fn commit_value(&mut self, row: usize, scratch: &mut Scratch, prekey: &Prekey) -> Result<bool> {
        if self.read_only {
            self.status = "read-only session — Esc to conceal".into();
            return Ok(false);
        }
        if let Err(e) = validate_raw_value(scratch.as_str()) {
            self.status = format!("invalid value: {e}");
            return Ok(false);
        }
        let generation = self.doc.bump_gen();
        if let Some(Row::Entry(entry)) = self.doc.rows.get_mut(row) {
            match SealedCell::seal(prekey, &entry.name, generation, scratch.as_bytes()) {
                Ok(new_cell) => {
                    let old = std::mem::replace(&mut entry.cell, new_cell);
                    entry.undo.push(old);
                    self.dirty = true;
                }
                Err(e) => {
                    self.status = format!("cannot seal value: {e}");
                    return Ok(false);
                }
            }
        }
        scratch.wipe();
        Ok(true)
    }

    /// Idle timer: re-seal a revealed value after IDLE_RESEAL of inactivity.
    pub fn tick(&mut self, scratch: &mut Scratch, prekey: &Prekey) -> Result<()> {
        if let Mode::EditValue { row, .. } = self.mode {
            if self.last_activity.elapsed() >= IDLE_RESEAL {
                if self.commit_value(row, scratch, prekey)? {
                    self.set_status("value re-sealed after 30s idle");
                } else {
                    scratch.wipe();
                    self.set_status("reveal timed out; edits discarded (value did not validate)");
                }
                self.mode = Mode::Browse;
            }
        }
        Ok(())
    }

    /// Force-conceal. Returns false when a revealed value could NOT be
    /// committed (invalid/seal failure) — the caller must not treat the
    /// document as consistent (audit fix 12): the mode is left in EditValue
    /// and the scratch intact so the user can fix or Esc.
    pub fn conceal(&mut self, scratch: &mut Scratch, prekey: &Prekey) -> Result<bool> {
        if let Mode::EditValue { row, cursor } = self.mode {
            if !self.commit_value(row, scratch, prekey)? {
                self.mode = Mode::EditValue { row, cursor };
                return Ok(false);
            }
            self.mode = Mode::Browse;
        }
        scratch.wipe();
        Ok(true)
    }

    /// Bracketed paste (audit fix 10). Only meaningful while editing; a paste
    /// containing newlines is rejected whole (values are single-line).
    pub fn handle_paste(&mut self, text: &str, scratch: &mut Scratch) -> Result<()> {
        self.last_activity = Instant::now();
        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::EditValue { row, mut cursor } => {
                if text.contains('\n') || text.contains('\r') {
                    self.set_status("paste rejected: contains line breaks (values are single-line)");
                } else {
                    for c in text.chars().filter(|c| !c.is_control()) {
                        match scratch.insert_char(cursor, c) {
                            Ok(()) => cursor += c.len_utf8(),
                            Err(e) => {
                                self.set_status(e.to_string());
                                break;
                            }
                        }
                    }
                }
                self.mode = Mode::EditValue { row, cursor };
            }
            Mode::EditText { row, kind, mut buf, mut cursor } => {
                if text.contains('\n') || text.contains('\r') {
                    self.set_status("paste rejected: contains line breaks");
                } else {
                    for c in text.chars().filter(|c| !c.is_control()) {
                        buf.insert(cursor, c);
                        cursor += c.len_utf8();
                    }
                }
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            other => {
                self.mode = other;
                self.set_status("paste ignored (reveal a value first)");
            }
        }
        Ok(())
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        scratch: &mut Scratch,
        prekey: &Prekey,
    ) -> Result<Action> {
        if key.kind != KeyEventKind::Press {
            return Ok(Action::Continue);
        }
        self.last_activity = Instant::now();
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        // Global shortcuts. Ctrl+C is an explicit quit request (audit fix 9):
        // in raw mode it arrives as a key event, and silently swallowing it —
        // or worse, dispatching 'c' — would betray every terminal instinct.
        if ctrl && key.code == KeyCode::Char('s') {
            if self.read_only {
                self.set_status("read-only session (recovery identity; no local key to re-encrypt with)");
                return Ok(Action::Continue);
            }
            if !self.conceal(scratch, prekey)? {
                self.status = format!("{} — fix or Esc this value before saving", self.status);
                return Ok(Action::Continue);
            }
            return Ok(Action::Save);
        }
        if ctrl && (key.code == KeyCode::Char('q') || key.code == KeyCode::Char('c')) {
            scratch.wipe();
            if self.dirty {
                self.mode = Mode::ConfirmQuit;
                return Ok(Action::Continue);
            }
            return Ok(Action::Quit);
        }
        if ctrl {
            // No other modified key means anything: never fall through to the
            // unmodified Char arms (audit fix 9).
            return Ok(Action::Continue);
        }

        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::Browse => self.key_browse(key, scratch, prekey),
            Mode::EditValue { row, cursor } => self.key_edit_value(key, row, cursor, scratch, prekey),
            Mode::EditText { row, kind, buf, cursor } => {
                self.key_edit_text(key, row, kind, buf, cursor, scratch, prekey)
            }
            Mode::ConfirmDelete(row) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if row < self.doc.rows.len() {
                            self.doc.rows.remove(row);
                        }
                        self.sel = self.sel.min(self.doc.rows.len().saturating_sub(1));
                        self.dirty = true;
                        self.set_status("entry deleted");
                    }
                    _ => self.set_status("delete cancelled"),
                }
                Ok(Action::Continue)
            }
            Mode::ConfirmQuit => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => Ok(Action::Quit),
                _ => {
                    self.set_status(if self.read_only {
                        "quit cancelled"
                    } else {
                        "quit cancelled (Ctrl+S saves)"
                    });
                    Ok(Action::Continue)
                }
            },
        }
    }

    fn block_if_read_only(&mut self) -> bool {
        if self.read_only {
            self.set_status("read-only session — viewing only");
            true
        } else {
            false
        }
    }

    fn key_browse(&mut self, key: KeyEvent, scratch: &mut Scratch, prekey: &Prekey) -> Result<Action> {
        self.mode = Mode::Browse;
        let last = self.doc.rows.len().saturating_sub(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.sel = (self.sel + 1).min(last),
            KeyCode::PageUp => self.sel = self.sel.saturating_sub(PAGE_JUMP),
            KeyCode::PageDown => self.sel = (self.sel + PAGE_JUMP).min(last),
            KeyCode::Home | KeyCode::Char('g') => self.sel = 0,
            KeyCode::End | KeyCode::Char('G') => self.sel = last,
            KeyCode::Enter | KeyCode::Char('e') => {
                let is_comment = matches!(self.doc.rows.get(self.sel), Some(Row::Comment { .. }));
                if is_comment && self.block_if_read_only() {
                    return Ok(Action::Continue);
                }
                match self.doc.rows.get(self.sel) {
                    Some(Row::Entry(entry)) => {
                        let cell = &entry.cell;
                        let name = entry.name.clone();
                        scratch.load_with(|buf| cell.open(prekey, &name, buf))?;
                        self.mode = Mode::EditValue { row: self.sel, cursor: scratch.len() };
                        self.set_status(if self.read_only {
                            "viewing value — Esc conceals (read-only)"
                        } else {
                            "editing value — Enter commits, Esc discards"
                        });
                    }
                    Some(Row::Comment { text, .. }) => {
                        let buf = text.clone();
                        let cursor = buf.len();
                        self.mode =
                            Mode::EditText { row: self.sel, kind: TextKind::Comment, buf, cursor };
                    }
                    _ => {}
                }
            }
            KeyCode::Char('r') => {
                if self.block_if_read_only() {
                    return Ok(Action::Continue);
                }
                if let Some(Row::Entry(entry)) = self.doc.rows.get(self.sel) {
                    let buf = entry.name.clone();
                    let cursor = buf.len();
                    self.mode = Mode::EditText { row: self.sel, kind: TextKind::Rename, buf, cursor };
                }
            }
            KeyCode::Char('a') => {
                if self.block_if_read_only() {
                    return Ok(Action::Continue);
                }
                let row = (self.sel + 1).min(self.doc.rows.len());
                self.mode =
                    Mode::EditText { row, kind: TextKind::NewEntryName, buf: String::new(), cursor: 0 };
                self.set_status("new variable name — Enter to continue, Esc to cancel");
            }
            KeyCode::Char('c') => {
                if self.block_if_read_only() {
                    return Ok(Action::Continue);
                }
                // Nothing is inserted until Enter (audit fix 13).
                let row = (self.sel + 1).min(self.doc.rows.len());
                let buf = "# ".to_string();
                let cursor = buf.len();
                self.mode = Mode::EditText { row, kind: TextKind::NewComment, buf, cursor };
                self.set_status("new comment — Enter to insert, Esc to cancel");
            }
            KeyCode::Char('d') => {
                if self.block_if_read_only() {
                    return Ok(Action::Continue);
                }
                match self.doc.rows.get(self.sel) {
                    Some(Row::Entry(_)) => self.mode = Mode::ConfirmDelete(self.sel),
                    Some(_) => {
                        self.doc.rows.remove(self.sel);
                        self.sel = self.sel.min(self.doc.rows.len().saturating_sub(1));
                        self.dirty = true;
                    }
                    None => {}
                }
            }
            KeyCode::Char('u') => {
                if self.block_if_read_only() {
                    return Ok(Action::Continue);
                }
                if let Some(Row::Entry(entry)) = self.doc.rows.get_mut(self.sel) {
                    if let Some(prev) = entry.undo.pop() {
                        entry.cell = prev;
                        self.dirty = true;
                        self.set_status("value restored to previous version");
                    } else {
                        self.set_status("no undo history for this entry");
                    }
                }
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    fn key_edit_value(
        &mut self,
        key: KeyEvent,
        row: usize,
        mut cursor: usize,
        scratch: &mut Scratch,
        prekey: &Prekey,
    ) -> Result<Action> {
        match key.code {
            KeyCode::Enter => {
                if self.commit_value(row, scratch, prekey)? {
                    self.set_status("value sealed");
                    self.mode = Mode::Browse;
                } else {
                    self.mode = Mode::EditValue { row, cursor };
                }
            }
            KeyCode::Esc => {
                scratch.wipe();
                self.set_status(if self.read_only { "concealed" } else { "edits discarded" });
                self.mode = Mode::Browse;
            }
            KeyCode::Left => {
                cursor = prev_boundary(scratch.as_str(), cursor);
                self.mode = Mode::EditValue { row, cursor };
            }
            KeyCode::Right => {
                cursor = next_boundary(scratch.as_str(), cursor);
                self.mode = Mode::EditValue { row, cursor };
            }
            KeyCode::Home => self.mode = Mode::EditValue { row, cursor: 0 },
            KeyCode::End => self.mode = Mode::EditValue { row, cursor: scratch.len() },
            KeyCode::Backspace => {
                let prev = prev_boundary(scratch.as_str(), cursor);
                scratch.delete_range(prev, cursor - prev);
                self.mode = Mode::EditValue { row, cursor: prev };
            }
            KeyCode::Delete => {
                let next = next_boundary(scratch.as_str(), cursor);
                scratch.delete_range(cursor, next - cursor);
                self.mode = Mode::EditValue { row, cursor };
            }
            KeyCode::Char(c) if !c.is_control() => {
                match scratch.insert_char(cursor, c) {
                    Ok(()) => cursor += c.len_utf8(),
                    Err(e) => self.set_status(e.to_string()),
                }
                self.mode = Mode::EditValue { row, cursor };
            }
            _ => self.mode = Mode::EditValue { row, cursor },
        }
        Ok(Action::Continue)
    }

    #[allow(clippy::too_many_arguments)]
    fn key_edit_text(
        &mut self,
        key: KeyEvent,
        row: usize,
        kind: TextKind,
        mut buf: String,
        mut cursor: usize,
        scratch: &mut Scratch,
        prekey: &Prekey,
    ) -> Result<Action> {
        match key.code {
            KeyCode::Enter => {
                match kind {
                    TextKind::Comment => {
                        let text = normalize_comment(buf);
                        if let Some(slot) = self.doc.rows.get_mut(row) {
                            let crlf = slot.crlf();
                            *slot = if text.trim().is_empty() {
                                Row::Blank { text: String::new(), crlf }
                            } else {
                                Row::Comment { text, crlf }
                            };
                            self.dirty = true;
                        }
                        self.mode = Mode::Browse;
                    }
                    TextKind::NewComment => {
                        let text = normalize_comment(buf);
                        let insert_at = row.min(self.doc.rows.len());
                        self.doc.rows.insert(
                            insert_at,
                            if text.trim().is_empty() {
                                Row::Blank { text: String::new(), crlf: false }
                            } else {
                                Row::Comment { text, crlf: false }
                            },
                        );
                        self.sel = insert_at;
                        self.dirty = true;
                        self.mode = Mode::Browse;
                    }
                    TextKind::Rename => {
                        let new_name = buf.trim().to_string();
                        if !is_valid_name(&new_name) {
                            self.set_status(format!("invalid variable name {new_name:?}"));
                            self.mode = Mode::EditText { row, kind, buf, cursor };
                            return Ok(Action::Continue);
                        }
                        // Re-seal under the new name (cells are AAD-bound to
                        // their slot name); the undo ring is sealed under the
                        // OLD name and must be dropped (audit fix 15).
                        let generation = self.doc.bump_gen();
                        let duplicate = self.doc.has_other_entry_named(&new_name, row);
                        if let Some(Row::Entry(entry)) = self.doc.rows.get_mut(row) {
                            let old_name = entry.name.clone();
                            scratch.load_with(|b| entry.cell.open(prekey, &old_name, b))?;
                            match SealedCell::seal(prekey, &new_name, generation, scratch.as_bytes())
                            {
                                Ok(cell) => {
                                    entry.cell = cell;
                                    scratch.wipe();
                                    entry.undo = SealedRing::new(UNDO_DEPTH);
                                    let had_export =
                                        entry.before_eq.trim_start().starts_with("export ");
                                    entry.before_eq = if had_export {
                                        format!("export {new_name}")
                                    } else {
                                        new_name.clone()
                                    };
                                    entry.name = new_name.clone();
                                    self.dirty = true;
                                    self.status = if duplicate {
                                        format!(
                                            "renamed — WARNING: another entry is also named \
                                             {new_name:?} (last one wins at runtime)"
                                        )
                                    } else {
                                        "renamed (undo history reset)".into()
                                    };
                                }
                                Err(e) => {
                                    scratch.wipe();
                                    self.status = format!("rename failed: {e}");
                                }
                            }
                        }
                        self.mode = Mode::Browse;
                    }
                    TextKind::NewEntryName => {
                        let name = buf.trim().to_string();
                        if !is_valid_name(&name) {
                            self.set_status(format!("invalid variable name {name:?}"));
                            self.mode = Mode::EditText { row, kind, buf, cursor };
                            return Ok(Action::Continue);
                        }
                        let generation = self.doc.bump_gen();
                        let duplicate = self.doc.has_other_entry_named(&name, usize::MAX);
                        match SealedCell::seal(prekey, &name, generation, b"") {
                            Ok(cell) => {
                                let insert_at = row.min(self.doc.rows.len());
                                self.doc.rows.insert(
                                    insert_at,
                                    Row::Entry(EntryRow {
                                        before_eq: name.clone(),
                                        name: name.clone(),
                                        cell,
                                        undo: SealedRing::new(UNDO_DEPTH),
                                        crlf: false,
                                    }),
                                );
                                self.sel = insert_at;
                                self.dirty = true;
                                scratch.wipe();
                                self.mode = Mode::EditValue { row: insert_at, cursor: 0 };
                                self.status = if duplicate {
                                    format!(
                                        "WARNING: another entry is also named {name:?} — \
                                         enter the value"
                                    )
                                } else {
                                    "enter the value — Enter commits".into()
                                };
                            }
                            Err(e) => {
                                self.status = format!("cannot create entry: {e}");
                                self.mode = Mode::Browse;
                            }
                        }
                    }
                }
            }
            KeyCode::Esc => {
                self.set_status("cancelled");
                self.mode = Mode::Browse;
            }
            KeyCode::Left => {
                cursor = prev_boundary(&buf, cursor);
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            KeyCode::Right => {
                cursor = next_boundary(&buf, cursor);
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            KeyCode::Home => self.mode = Mode::EditText { row, kind, buf, cursor: 0 },
            KeyCode::End => {
                cursor = buf.len();
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            KeyCode::Backspace => {
                let prev = prev_boundary(&buf, cursor);
                buf.replace_range(prev..cursor, "");
                cursor = prev;
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            KeyCode::Delete => {
                let next = next_boundary(&buf, cursor);
                buf.replace_range(cursor..next, "");
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            KeyCode::Char(c) if !c.is_control() => {
                buf.insert(cursor, c);
                cursor += c.len_utf8();
                self.mode = Mode::EditText { row, kind, buf, cursor };
            }
            _ => self.mode = Mode::EditText { row, kind, buf, cursor },
        }
        Ok(Action::Continue)
    }
}

fn normalize_comment(buf: String) -> String {
    if buf.trim().is_empty() || buf.trim_start().starts_with('#') {
        buf
    } else {
        format!("# {buf}")
    }
}

fn prev_boundary(s: &str, at: usize) -> usize {
    if at == 0 {
        return 0;
    }
    let mut i = at - 1;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn next_boundary(s: &str, at: usize) -> usize {
    if at >= s.len() {
        return s.len();
    }
    let mut i = at + 1;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

// ---- rendering --------------------------------------------------------------

/// What occupies one visual slot: a real document row, or the virtual
/// (not-yet-inserted) row being typed for NewEntryName/NewComment.
enum Visual {
    Real(usize),
    Pending,
}

pub fn draw(frame: &mut Frame<'_>, state: &mut FormState, scratch: &Scratch) {
    let [title_area, list_area, status_area, help_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    // Title.
    let dirty = if state.dirty { " [modified]" } else { "" };
    let ro = if state.read_only { " [read-only]" } else { "" };
    frame.render_widget(
        UiLine::from(vec![Span::styled(
            format!(" ai-env edit \u{2014} {}{dirty}{ro}", state.file_name),
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        title_area,
    );

    // Virtual pending row (audit fix 14): rendered as an inserted line, never
    // as an overlay hiding a real row.
    let pending: Option<usize> = match &state.mode {
        Mode::EditText { row, kind, .. } if kind.is_virtual() => Some(*row),
        _ => None,
    };
    let total = state.doc.rows.len() + usize::from(pending.is_some());
    let focus = match (&state.mode, pending) {
        (Mode::EditText { .. }, Some(p)) => p,
        _ => visual_index_of(state.sel, pending),
    };

    // Keep the focused visual slot scrolled into view.
    let height = list_area.height as usize;
    if focus < state.scroll {
        state.scroll = focus;
    } else if height > 0 && focus >= state.scroll + height {
        state.scroll = focus + 1 - height;
    }

    for (vis, vslot) in (state.scroll..total).take(height.max(1)).enumerate() {
        let row_area = Rect::new(list_area.x, list_area.y + vis as u16, list_area.width, 1);
        let visual = match pending {
            Some(p) if vslot == p => Visual::Pending,
            Some(p) if vslot > p => Visual::Real(vslot - 1),
            _ => Visual::Real(vslot),
        };
        let line: UiLine<'_> = match visual {
            Visual::Pending => {
                if let Mode::EditText { buf, cursor, .. } = &state.mode {
                    frame.set_cursor_position((
                        row_area.x + 2 + width_of(&buf[..*cursor]),
                        row_area.y,
                    ));
                    UiLine::from(vec![
                        Span::raw("  "),
                        Span::styled(buf.as_str(), Style::default().fg(Color::Green)),
                    ])
                } else {
                    UiLine::from("")
                }
            }
            Visual::Real(idx) => {
                let selected = idx == state.sel && pending.is_none();
                let base = if selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                match (&state.doc.rows[idx], &state.mode) {
                    (_, Mode::EditText { row, kind, buf, cursor }) if !kind.is_virtual() && *row == idx => {
                        frame.set_cursor_position((
                            row_area.x + 2 + width_of(&buf[..*cursor]),
                            row_area.y,
                        ));
                        UiLine::from(vec![Span::raw("  "), Span::styled(buf.as_str(), base)])
                    }
                    (Row::Entry(entry), Mode::EditValue { row, cursor }) if *row == idx => {
                        // Horizontal windowing (audit fix 20): keep the cursor
                        // visible for values wider than the terminal.
                        let prefix = format!("  {} = ", entry.name);
                        let avail = (row_area.width as usize)
                            .saturating_sub(prefix.chars().count() + 1);
                        let (window, cursor_cols) =
                            window_around(scratch.as_str(), *cursor, avail);
                        frame.set_cursor_position((
                            row_area.x + width_of(&prefix) + cursor_cols,
                            row_area.y,
                        ));
                        UiLine::from(vec![
                            Span::styled(prefix, Style::default().fg(Color::Cyan)),
                            // Borrowed, not cloned (audit fix 3).
                            Span::styled(window, Style::default().fg(Color::Yellow)),
                        ])
                    }
                    (Row::Entry(entry), _) => UiLine::from(vec![
                        Span::styled(format!("  {}", entry.name), base.fg(Color::Cyan)),
                        Span::styled(" = ", base),
                        Span::styled(MASK, base.fg(Color::DarkGray)),
                        Span::styled(
                            if entry.undo.len() > 0 {
                                format!("  ({} undo)", entry.undo.len())
                            } else {
                                String::new()
                            },
                            base.fg(Color::DarkGray),
                        ),
                    ]),
                    (Row::Comment { text, .. }, _) => {
                        UiLine::from(Span::styled(format!("  {text}"), base.fg(Color::DarkGray)))
                    }
                    (Row::Blank { .. }, _) => UiLine::from(Span::styled("  ", base)),
                }
            }
        };
        frame.render_widget(line, row_area);
    }

    // Status / confirm prompts.
    let status = match &state.mode {
        Mode::ConfirmDelete(_) => "delete this entry? [y/N]".to_owned(),
        Mode::ConfirmQuit => {
            if state.read_only {
                "quit? [y/N]".to_owned()
            } else {
                "quit WITHOUT saving? [y/N]  (Ctrl+S saves)".to_owned()
            }
        }
        _ => state.status.clone(),
    };
    frame.render_widget(
        UiLine::from(Span::styled(format!(" {status}"), Style::default().fg(Color::Yellow))),
        status_area,
    );

    // Help line.
    let help = match &state.mode {
        Mode::Browse => {
            if state.read_only {
                "\u{2191}\u{2193} move · Enter reveal · Esc conceal · Ctrl+Q quit (read-only)"
            } else {
                "\u{2191}\u{2193} move · Enter reveal/edit · a add · c comment · r rename · d delete · u undo · Ctrl+S save · Ctrl+Q quit"
            }
        }
        Mode::EditValue { .. } => "Enter seal · Esc discard · values re-seal after 30s idle",
        Mode::EditText { .. } => "Enter confirm · Esc cancel",
        _ => "",
    };
    frame.render_widget(
        UiLine::from(Span::styled(format!(" {help}"), Style::default().fg(Color::DarkGray))),
        help_area,
    );
}

/// Map a document row index to its visual slot given a pending insertion.
fn visual_index_of(row: usize, pending: Option<usize>) -> usize {
    match pending {
        Some(p) if row >= p => row + 1,
        _ => row,
    }
}

/// Char-windowing for wide values: returns the visible slice and the cursor's
/// column offset within it (both in char-columns).
fn window_around(s: &str, cursor: usize, width: usize) -> (&str, u16) {
    if width == 0 {
        return ("", 0);
    }
    let cursor_chars = s[..cursor.min(s.len())].chars().count();
    let total_chars = s.chars().count();
    let start_chars = if cursor_chars >= width { cursor_chars + 1 - width } else { 0 };
    let end_chars = (start_chars + width).min(total_chars);
    let byte_at = |n: usize| s.char_indices().nth(n).map_or(s.len(), |(i, _)| i);
    let start = byte_at(start_chars);
    let end = byte_at(end_chars);
    (&s[start..end], (cursor_chars - start_chars) as u16)
}

fn width_of(s: &str) -> u16 {
    s.chars().count() as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dotenv::parse_lines;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn setup(input: &str) -> (FormState, Scratch, Prekey) {
        let prekey = Prekey::new().unwrap();
        let raw = parse_lines(input).unwrap();
        let doc = Document::seal_from(raw, &prekey).unwrap();
        (FormState::new(doc, ".env".into(), false), Scratch::new().unwrap(), prekey)
    }

    fn value_of(state: &FormState, row: usize, prekey: &Prekey) -> String {
        match &state.doc.rows[row] {
            Row::Entry(e) => {
                let mut buf = [0u8; 4096];
                let n = e.cell.open(prekey, &e.name, &mut buf).unwrap();
                String::from_utf8_lossy(&buf[..n]).into_owned()
            }
            _ => panic!("row {row} is not an entry"),
        }
    }

    #[test]
    fn reveal_edit_commit_reseal() {
        let (mut st, mut scratch, prekey) = setup("A=one\nB=two\n");
        assert_eq!(st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap(), Action::Continue);
        assert!(matches!(st.mode, Mode::EditValue { row: 0, .. }));
        assert_eq!(scratch.as_str(), "one");
        st.handle_key(key(KeyCode::Char('X')), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::Browse));
        assert_eq!(scratch.len(), 0, "scratch wiped after commit");
        assert!(st.dirty);
        assert_eq!(value_of(&st, 0, &prekey), "oneX");
        assert_eq!(value_of(&st, 1, &prekey), "two");
    }

    #[test]
    fn esc_discards_edits() {
        let (mut st, mut scratch, prekey) = setup("A=one\n");
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Char('Z')), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Esc), &mut scratch, &prekey).unwrap();
        assert_eq!(scratch.len(), 0);
        assert!(!st.dirty);
        assert_eq!(value_of(&st, 0, &prekey), "one");
    }

    /// Audit fix 9: modified keys never dispatch Browse commands; Ctrl+C is a
    /// quit request.
    #[test]
    fn ctrl_modified_keys_are_safe_in_browse() {
        let (mut st, mut scratch, prekey) = setup("A=1\nB=2\n");
        // Ctrl+D must NOT start a delete, Ctrl+U must NOT undo, Ctrl+E must
        // NOT reveal.
        for c in ['d', 'u', 'e', 'a', 'r'] {
            assert_eq!(st.handle_key(ctrl(c), &mut scratch, &prekey).unwrap(), Action::Continue);
            assert!(matches!(st.mode, Mode::Browse), "Ctrl+{c} changed mode");
            assert!(!st.dirty, "Ctrl+{c} dirtied the doc");
        }
        assert_eq!(st.doc.rows.len(), 2);
        // Ctrl+C quits (clean doc → immediate quit).
        assert_eq!(st.handle_key(ctrl('c'), &mut scratch, &prekey).unwrap(), Action::Quit);
    }

    /// Audit fix 10: paste semantics per mode.
    #[test]
    fn paste_rules() {
        let (mut st, mut scratch, prekey) = setup("A=1\nB=2\n");
        // Browse: ignored entirely (a paste of "dyd" must not delete rows).
        st.handle_paste("dydy", &mut scratch).unwrap();
        assert_eq!(st.doc.rows.len(), 2);
        assert!(st.status.contains("paste ignored"));
        // EditValue: inserted; multi-line rejected whole.
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        st.handle_paste("pasted", &mut scratch).unwrap();
        assert_eq!(scratch.as_str(), "1pasted");
        st.handle_paste("bad\nline", &mut scratch).unwrap();
        assert_eq!(scratch.as_str(), "1pasted", "multi-line paste must be rejected whole");
        assert!(st.status.contains("rejected"));
        st.handle_key(key(KeyCode::Esc), &mut scratch, &prekey).unwrap();
    }

    /// Audit fix 11: overlong values are a status, never a session-fatal.
    #[test]
    fn overlong_value_is_survivable() {
        let (mut st, mut scratch, prekey) = setup("A=x\n");
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        // Fill right up to the cap via paste, then one more char.
        let big = "y".repeat(super::super::cells::MAX_VALUE - 1);
        st.handle_paste(&big, &mut scratch).unwrap();
        assert_eq!(scratch.len(), super::super::cells::MAX_VALUE);
        let r = st.handle_key(key(KeyCode::Char('z')), &mut scratch, &prekey).unwrap();
        assert_eq!(r, Action::Continue, "must not kill the session");
        assert!(st.status.contains("value full"));
        assert_eq!(scratch.len(), super::super::cells::MAX_VALUE);
        // And commit still works.
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::Browse));
    }

    /// Audit fix 12: Ctrl+S with an invalid revealed value must NOT save.
    #[test]
    fn ctrl_s_blocks_on_invalid_value() {
        let (mut st, mut scratch, prekey) = setup("A=ok\n");
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Home), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Char('"')), &mut scratch, &prekey).unwrap();
        let r = st.handle_key(ctrl('s'), &mut scratch, &prekey).unwrap();
        assert_eq!(r, Action::Continue, "save must be blocked");
        assert!(matches!(st.mode, Mode::EditValue { .. }), "stay editing to fix it");
        assert!(st.status.contains("fix or Esc"));
        assert_eq!(value_of(&st, 0, &prekey), "ok", "cell unchanged");
        // Esc then save works.
        st.handle_key(key(KeyCode::Esc), &mut scratch, &prekey).unwrap();
        assert_eq!(st.handle_key(ctrl('s'), &mut scratch, &prekey).unwrap(), Action::Save);
    }

    /// Audit fix 13: 'c' inserts nothing until Enter; Esc leaves no trace.
    #[test]
    fn new_comment_is_transactional() {
        let (mut st, mut scratch, prekey) = setup("A=1\n");
        st.handle_key(key(KeyCode::Char('c')), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 1, "nothing inserted yet");
        st.handle_key(key(KeyCode::Esc), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 1);
        assert!(!st.dirty, "cancelled comment must not dirty the doc");
        // Enter path inserts.
        st.handle_key(key(KeyCode::Char('c')), &mut scratch, &prekey).unwrap();
        for ch in "note".chars() {
            st.handle_key(key(KeyCode::Char(ch)), &mut scratch, &prekey).unwrap();
        }
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 2);
        assert!(st.dirty);
        assert!(matches!(&st.doc.rows[1], Row::Comment { text, .. } if text == "# note"));
    }

    /// Audit fix 15: rename drops the old-name-sealed undo ring.
    #[test]
    fn rename_reseals_and_clears_ring() {
        let (mut st, mut scratch, prekey) = setup("OLD=secret\n");
        // Build some history first.
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Char('2')), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        match &st.doc.rows[0] {
            Row::Entry(e) => assert_eq!(e.undo.len(), 1),
            _ => panic!(),
        }
        // Rename.
        st.handle_key(key(KeyCode::Char('r')), &mut scratch, &prekey).unwrap();
        for _ in 0..3 {
            st.handle_key(key(KeyCode::Backspace), &mut scratch, &prekey).unwrap();
        }
        for c in "NEW".chars() {
            st.handle_key(key(KeyCode::Char(c)), &mut scratch, &prekey).unwrap();
        }
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        match &st.doc.rows[0] {
            Row::Entry(e) => {
                assert_eq!(e.name, "NEW");
                assert_eq!(e.undo.len(), 0, "ring sealed under OLD must be dropped");
            }
            _ => panic!(),
        }
        assert_eq!(value_of(&st, 0, &prekey), "secret2");
        // 'u' after rename: harmless no-history status, session alive.
        let r = st.handle_key(key(KeyCode::Char('u')), &mut scratch, &prekey).unwrap();
        assert_eq!(r, Action::Continue);
        assert!(st.status.contains("no undo history"));
    }

    /// Audit fix 18: duplicate names warn.
    #[test]
    fn duplicate_name_warns() {
        let (mut st, mut scratch, prekey) = setup("A=1\nB=2\n");
        st.handle_key(key(KeyCode::Char('a')), &mut scratch, &prekey).unwrap();
        for c in "B".chars() {
            st.handle_key(key(KeyCode::Char(c)), &mut scratch, &prekey).unwrap();
        }
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert!(st.status.contains("WARNING"), "status: {}", st.status);
        assert!(st.status.contains("\"B\""));
    }

    /// Audit fix 19: read-only sessions cannot mutate.
    #[test]
    fn read_only_blocks_mutation() {
        let prekey = Prekey::new().unwrap();
        let doc = Document::seal_from(parse_lines("A=1\n# c\n").unwrap(), &prekey).unwrap();
        let mut st = FormState::new(doc, ".env".into(), true);
        let mut scratch = Scratch::new().unwrap();
        for c in ['a', 'c', 'd', 'r', 'u'] {
            st.handle_key(key(KeyCode::Char(c)), &mut scratch, &prekey).unwrap();
            assert!(matches!(st.mode, Mode::Browse), "{c} must be blocked");
            assert!(!st.dirty);
        }
        assert_eq!(st.doc.rows.len(), 2);
        // Reveal is allowed; commit is blocked.
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::EditValue { .. }));
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::EditValue { .. }), "commit blocked, stay revealed");
        assert!(st.status.contains("read-only"));
        st.handle_key(key(KeyCode::Esc), &mut scratch, &prekey).unwrap();
        // Ctrl+S blocked.
        assert_eq!(st.handle_key(ctrl('s'), &mut scratch, &prekey).unwrap(), Action::Continue);
        assert!(st.status.contains("read-only"));
    }

    /// Audit fix 14: NewEntryName is a virtual row — nothing exists until Enter.
    #[test]
    fn add_entry_flow_and_cancel() {
        let (mut st, mut scratch, prekey) = setup("A=1\n");
        st.handle_key(key(KeyCode::Char('a')), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 1, "virtual until Enter");
        st.handle_key(key(KeyCode::Esc), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 1);
        assert!(!st.dirty);
        st.handle_key(key(KeyCode::Char('a')), &mut scratch, &prekey).unwrap();
        for c in "NEW_KEY".chars() {
            st.handle_key(key(KeyCode::Char(c)), &mut scratch, &prekey).unwrap();
        }
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::EditValue { row: 1, .. }));
        for c in "val".chars() {
            st.handle_key(key(KeyCode::Char(c)), &mut scratch, &prekey).unwrap();
        }
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 2);
        assert_eq!(value_of(&st, 1, &prekey), "val");
    }

    #[test]
    fn idle_tick_reseals_valid_edit() {
        let (mut st, mut scratch, prekey) = setup("A=one\n");
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Char('!')), &mut scratch, &prekey).unwrap();
        st.last_activity = Instant::now() - IDLE_RESEAL - Duration::from_secs(1);
        st.tick(&mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::Browse));
        assert_eq!(scratch.len(), 0);
        assert_eq!(value_of(&st, 0, &prekey), "one!");
    }

    #[test]
    fn quit_confirms_when_dirty() {
        let (mut st, mut scratch, prekey) = setup("A=1\n");
        assert_eq!(st.handle_key(ctrl('q'), &mut scratch, &prekey).unwrap(), Action::Quit);
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Char('x')), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Enter), &mut scratch, &prekey).unwrap();
        assert_eq!(st.handle_key(ctrl('q'), &mut scratch, &prekey).unwrap(), Action::Continue);
        assert!(matches!(st.mode, Mode::ConfirmQuit));
        assert_eq!(st.handle_key(key(KeyCode::Char('y')), &mut scratch, &prekey).unwrap(), Action::Quit);
    }

    #[test]
    fn delete_needs_confirmation_for_entries() {
        let (mut st, mut scratch, prekey) = setup("A=1\nB=2\n");
        st.handle_key(key(KeyCode::Char('d')), &mut scratch, &prekey).unwrap();
        assert!(matches!(st.mode, Mode::ConfirmDelete(0)));
        st.handle_key(key(KeyCode::Char('n')), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 2);
        st.handle_key(key(KeyCode::Char('d')), &mut scratch, &prekey).unwrap();
        st.handle_key(key(KeyCode::Char('y')), &mut scratch, &prekey).unwrap();
        assert_eq!(st.doc.rows.len(), 1);
    }

    /// Audit fix 16: CRLF endings survive the document model.
    #[test]
    fn crlf_rows_preserved() {
        let prekey = Prekey::new().unwrap();
        let doc =
            Document::seal_from(parse_lines("A=one\r\nB=two\n").unwrap(), &prekey).unwrap();
        assert!(doc.rows[0].crlf());
        assert!(!doc.rows[1].crlf());
        let st = FormState::new(doc, ".env".into(), false);
        assert_eq!(value_of(&st, 0, &prekey), "one", "CR must not be inside the value");
    }

    /// Audit fix 17: oversized value at load names the variable and line.
    #[test]
    fn oversized_value_load_error_is_actionable() {
        let prekey = Prekey::new().unwrap();
        let long = format!("BIG={}\n", "v".repeat(4500));
        let raw = parse_lines(&long).unwrap();
        let err = match Document::seal_from(raw, &prekey) {
            Err(e) => e,
            Ok(_) => panic!("oversized value must fail to seal"),
        };
        let msg = err.to_string();
        assert!(msg.contains("\"BIG\""), "must name the variable: {msg}");
        assert!(msg.contains("line 1"));
        assert!(msg.contains("decrypt --force"));
    }

    /// Audit fix 20: horizontal windowing keeps the cursor visible.
    #[test]
    fn window_around_wide_values() {
        let s = "abcdefghij"; // 10 chars
        let (w, c) = window_around(s, 0, 5);
        assert_eq!((w, c), ("abcde", 0));
        let (w, c) = window_around(s, 10, 5); // cursor at end
        assert_eq!(c as usize, 4);
        assert_eq!(w, "ghij"); // window shows the tail
        let (w, _) = window_around(s, 10, 50);
        assert_eq!(w, s);
        let (w, c) = window_around("", 0, 5);
        assert_eq!((w, c), ("", 0));
    }
}
