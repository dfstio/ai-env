//! `ai-env edit` — orchestration: harden → decrypt (one Touch ID prompt) →
//! parse layout-preserving → seal per value → run the form → streaming save.
mod cells;
mod form;
mod harden;
mod scratch;

use crate::age_cmd::AgeTool;
use crate::container;
use crate::errors::{CliError, Result};
use crate::select;
use crate::store::{write_atomic, Keystore};
use cells::Prekey;
use form::{Action, Document, FormState, Row};
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::{execute, terminal};
use scratch::Scratch;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

pub struct EditOpts {
    pub file: PathBuf,
    pub key: Option<String>,
    pub identity: Option<PathBuf>,
    pub insecure_terminal: bool,
}

pub fn run_edit(store: &Keystore, age: &AgeTool, opts: &EditOpts) -> Result<()> {
    harden::preflight(opts.insecure_terminal)?;

    // Symlinked targets are refused up front (write_atomic would refuse at
    // save anyway — better before the Touch ID prompt than after a session).
    if std::fs::symlink_metadata(&opts.file)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(CliError::Msg(format!(
            "{} is a symlink — refusing (operate on the target directly)",
            opts.file.display()
        )));
    }

    // Load + decrypt (container pre-flight decides 4/6 before age spawns).
    let text = std::fs::read_to_string(&opts.file)
        .map_err(|e| CliError::Msg(format!("cannot read {}: {e}", opts.file.display())))?;
    if !container::has_marker(&text) {
        return Err(CliError::Corrupt(format!(
            "{} is not an ai-env encrypted file — encrypt it first (ai-env encrypt)",
            opts.file.display()
        )));
    }
    let cont = container::read(&text)?;

    // Which key re-encrypts on save? With -i (recovery identity) there may be
    // no local key: the session is then read-only.
    let save_key = match &opts.identity {
        Some(_) => select::resolve_for_decrypt(store, opts.key.as_deref(), &cont).ok(),
        None => Some(select::resolve_for_decrypt(store, opts.key.as_deref(), &cont)?),
    };
    let identity_path = match &opts.identity {
        Some(p) => p.clone(),
        None => store.identity_path(save_key.as_deref().expect("resolved above")),
    };

    // ONE Touch ID prompt. The full plaintext exists only inside this
    // Zeroizing buffer, and only until per-value sealing below completes.
    let plaintext = age.decrypt_to_bytes(&identity_path, &cont.data)?;
    let prekey = Prekey::new()?;
    let doc = {
        let text = std::str::from_utf8(&plaintext)
            .map_err(|_| CliError::Msg("decrypted content is not UTF-8".into()))?;
        let raw = crate::dotenv::parse_lines(text)?;
        Document::seal_from(raw, &prekey)?
    };
    drop(plaintext); // zeroized

    let read_only = save_key.is_none();
    let mut state = FormState::new(
        doc,
        opts.file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        read_only,
    );
    if read_only {
        state.status =
            "recovery session: no local key for this file — viewing/editing only, save disabled"
                .into();
    } else {
        state.status = "sealed in memory: at most one value is ever plaintext".into();
    }
    let mut scratch = Scratch::new()?;

    // Terminal session with guaranteed cleanup (panic hook clears the
    // alternate screen BEFORE leaving it, so revealed cells never persist
    // in the primary buffer or restored sessions).
    let saved_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal(true);
        eprintln!("ai-env edit: internal error: {info}");
    }));
    terminal::enable_raw_mode()?;
    execute!(
        std::io::stdout(),
        terminal::EnterAlternateScreen,
        event::EnableBracketedPaste
    )?;
    let mut term = ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(
        std::io::stdout(),
    ))?;

    let result = event_loop(&mut term, &mut state, &mut scratch, &prekey, store, age, opts, save_key.as_deref());

    // Teardown: wipe secrets first, then clear + restore the terminal.
    // (An uncommittable value is force-wiped — quitting was the user's call.)
    if let Ok(false) | Err(_) = state.conceal(&mut scratch, &prekey) {
        scratch.wipe();
    }
    drop(scratch);
    drop(state); // sealed cells
    drop(prekey);
    let _ = term.clear();
    let _ = restore_terminal(false);
    std::panic::set_hook(saved_hook);
    result
}

fn restore_terminal(clear_first: bool) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    if clear_first {
        // Best-effort ANSI clear of the alternate screen from the panic path.
        let _ = out.write_all(b"\x1b[2J\x1b[H");
    }
    let _ = execute!(out, event::DisableBracketedPaste);
    execute!(out, terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()
}

#[allow(clippy::too_many_arguments)]
fn event_loop(
    term: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    state: &mut FormState,
    scratch: &mut Scratch,
    prekey: &Prekey,
    store: &Keystore,
    age: &AgeTool,
    opts: &EditOpts,
    save_key: Option<&str>,
) -> Result<()> {
    loop {
        term.draw(|frame| form::draw(frame, state, scratch))?;
        if event::poll(Duration::from_millis(500))? {
            match event::read()? {
                Event::Key(key) => match state.handle_key(key, scratch, prekey)? {
                    Action::Continue => {}
                    Action::Quit => return Ok(()),
                    Action::Save => {
                        let key_name = save_key.expect("save blocked in read-only mode");
                        match save(state, scratch, prekey, store, age, opts, key_name) {
                            Ok(()) => {
                                state.dirty = false;
                                state.status = format!("saved (re-encrypted with key {key_name:?})");
                            }
                            Err(e) => state.status = format!("SAVE FAILED: {e}"),
                        }
                    }
                },
                Event::Paste(text) => state.handle_paste(&text, scratch)?,
                Event::Resize(..) => {}
                _ => {}
            }
        }
        state.tick(scratch, prekey)?;
    }
}

/// Streaming save: unseal one cell at a time straight into age's stdin —
/// never a whole-file plaintext buffer — then wrap and atomically replace.
fn save(
    state: &mut FormState,
    scratch: &mut Scratch,
    prekey: &Prekey,
    store: &Keystore,
    age: &AgeTool,
    opts: &EditOpts,
    key_name: &str,
) -> Result<()> {
    let recipients = store.recipients_path(key_name);
    let rows = &state.doc.rows;
    let trailing = state.doc.trailing_newline;
    // The container cap `encrypt` enforces applies here too (audit fix 7):
    // count every byte before it enters the pipe.
    let mut written = 0usize;
    let result = age.encrypt_streaming(&recipients, |sink| {
        let mut put = |sink: &mut dyn Write, bytes: &[u8]| -> Result<()> {
            written += bytes.len();
            if written > container::MAX_PLAINTEXT {
                return Err(CliError::Msg(format!(
                    "file exceeds the {} KiB container cap — split it (nothing was written)",
                    container::MAX_PLAINTEXT / 1024
                )));
            }
            sink.write_all(bytes)?;
            Ok(())
        };
        let last = rows.len().saturating_sub(1);
        for (i, row) in rows.iter().enumerate() {
            match row {
                Row::Comment { text, .. } | Row::Blank { text, .. } => {
                    put(sink, text.as_bytes())?
                }
                Row::Entry(entry) => {
                    put(sink, entry.before_eq.as_bytes())?;
                    put(sink, b"=")?;
                    scratch.load_with(|buf| entry.cell.open(prekey, &entry.name, buf))?;
                    let r = put(sink, scratch.as_bytes());
                    scratch.wipe();
                    r?;
                }
            }
            if row.crlf() {
                put(sink, b"\r")?;
            }
            if i != last || trailing {
                put(sink, b"\n")?;
            }
        }
        Ok(())
    });
    // The scratch must never survive a failed save with plaintext in it
    // (audit fix 4) — wipe before propagating any error.
    scratch.wipe();
    let ciphertext = result?;
    write_atomic(&opts.file, container::write(&ciphertext).as_bytes())
}
