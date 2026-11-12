//! Who speaks on stderr (S8). The operator CLI says what it does in
//! `ai-env:` lines. The wrapper's stderr is what Cursor shows when a session
//! fails (`Claude Code process exited with code N. stderr: …`, its last
//! 2 KiB, and only for a non-zero exit), so the wrapper keeps its notes and
//! warnings in its log (`logs/wrapper.log`) and prints one line of its own,
//! the last: `ai-env-claude: <what failed and the fix>`. Code both share —
//! the VM selection, the locks, the credential steps — speaks through
//! [`note`], [`warn`] and [`line`]; each process picks its voice once, early
//! ([`set`]), and a process that never picks one is the CLI. (S8 wave 1, W2,
//! moves the shared call sites here and adds the `make lint` guard against
//! raw `ai-env:` writes in them.) The fork gap: [`echo`] repeats another
//! program's own line as it is, before that last line (the CLI's resume
//! miss, which Cursor's webview reads in the exit's stderr).
use std::io::Write;
use std::sync::OnceLock;

/// The two speakers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Voice {
    /// `ai-env`: every note, warning and line on stderr.
    Cli,
    /// `ai-env-claude`: notes and warnings to the log only; [`line`] alone on stderr.
    Wrapper,
}

impl Voice {
    /// The prefix of its stderr lines.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Voice::Cli => "ai-env",
            Voice::Wrapper => "ai-env-claude",
        }
    }
}

/// What a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// What is happening (`waiting for …`, `reusing …`).
    Note,
    /// Something the operator should know (`warning: …`).
    Warning,
    /// The one line a command ends with: always on stderr.
    Line,
    /// The fork gap: another program's own line, repeated as it is (no
    /// prefix): always on stderr, and never last ([`Kind::Line`] follows it).
    Echo,
}

/// The stderr line `voice` prints for `msg` of `kind`, or `None` when it goes
/// to the log only (the wrapper's notes and warnings).
#[must_use]
pub fn rendered(voice: Voice, kind: Kind, msg: &str) -> Option<String> {
    match (voice, kind) {
        (Voice::Wrapper, Kind::Note | Kind::Warning) => None,
        (_, Kind::Warning) => Some(format!("{}: warning: {msg}", voice.prefix())),
        (_, Kind::Note | Kind::Line) => Some(format!("{}: {msg}", voice.prefix())),
        (_, Kind::Echo) => Some(msg.to_string()),
    }
}

/// A process's voice, picked at most once.
#[derive(Debug, Default)]
pub struct Speaker {
    voice: OnceLock<Voice>,
}

impl Speaker {
    #[must_use]
    pub const fn new() -> Speaker {
        Speaker { voice: OnceLock::new() }
    }

    /// Pick the voice; `false` (and nothing changes) when one was picked already.
    pub fn set(&self, voice: Voice) -> bool {
        self.voice.set(voice).is_ok()
    }

    /// The voice picked, [`Voice::Cli`] until one is.
    #[must_use]
    pub fn voice(&self) -> Voice {
        self.voice.get().copied().unwrap_or(Voice::Cli)
    }

    /// Say `msg` as `kind`: one line into `stderr` (a closed stream is
    /// ignored, never a panic), or the log ([`rendered`] decides).
    pub fn speak(&self, kind: Kind, msg: &str, stderr: &mut dyn Write) {
        match rendered(self.voice(), kind, msg) {
            Some(line) => {
                let _ = writeln!(stderr, "{line}");
            }
            None if kind == Kind::Warning => tracing::warn!("{msg}"),
            None => tracing::info!("{msg}"),
        }
    }
}

/// This process's speaker.
static SPEAKER: Speaker = Speaker::new();

/// Pick this process's voice (the wrapper, before anything speaks); `false`
/// when one was picked already.
pub fn set(voice: Voice) -> bool {
    SPEAKER.set(voice)
}

/// This process's voice.
#[must_use]
pub fn voice() -> Voice {
    SPEAKER.voice()
}

/// This process's prefix: `ai-env` or `ai-env-claude`.
#[must_use]
pub fn prefix() -> &'static str {
    voice().prefix()
}

/// A note: on stderr for the CLI, to the log for the wrapper.
pub fn note(msg: &str) {
    SPEAKER.speak(Kind::Note, msg, &mut std::io::stderr().lock());
}

/// A warning: `<prefix>: warning: …` on stderr for the CLI, to the log for the wrapper.
pub fn warn(msg: &str) {
    SPEAKER.speak(Kind::Warning, msg, &mut std::io::stderr().lock());
}

/// `<prefix>: msg` on stderr, whoever speaks: the wrapper's one final line.
pub fn line(msg: &str) {
    SPEAKER.speak(Kind::Line, msg, &mut std::io::stderr().lock());
}

/// The fork gap (option B): `msg`, one line of another program's (the CLI's
/// resume miss: `remote::Failure::cli_line`), on stderr as it is, whoever
/// speaks; never the last line: the caller's [`line`] follows it.
pub fn echo(msg: &str) {
    SPEAKER.speak(Kind::Echo, msg, &mut std::io::stderr().lock());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_says_every_kind_on_stderr() {
        assert_eq!(rendered(Voice::Cli, Kind::Note, "waiting for the lock"), Some("ai-env: waiting for the lock".into()));
        assert_eq!(rendered(Voice::Cli, Kind::Warning, "no row"), Some("ai-env: warning: no row".into()));
        assert_eq!(rendered(Voice::Cli, Kind::Line, "refused"), Some("ai-env: refused".into()));
    }

    #[test]
    fn the_wrapper_logs_notes_and_warnings_and_prints_its_one_line() {
        assert_eq!(rendered(Voice::Wrapper, Kind::Note, "waiting for the lock"), None);
        assert_eq!(rendered(Voice::Wrapper, Kind::Warning, "no row"), None);
        assert_eq!(rendered(Voice::Wrapper, Kind::Line, "Touch ID was cancelled"), Some("ai-env-claude: Touch ID was cancelled".into()));
    }

    #[test]
    fn a_voice_is_picked_once_and_defaults_to_the_cli() {
        let s = Speaker::new();
        assert_eq!(s.voice(), Voice::Cli);
        assert!(s.set(Voice::Wrapper));
        assert!(!s.set(Voice::Cli), "the first pick wins");
        assert_eq!(s.voice(), Voice::Wrapper);
        assert_eq!((Voice::Cli.prefix(), Voice::Wrapper.prefix()), ("ai-env", "ai-env-claude"));
    }

    #[test]
    fn speak_writes_one_line_or_nothing() {
        let wrapper = Speaker::new();
        wrapper.set(Voice::Wrapper);
        let mut err = Vec::new();
        wrapper.speak(Kind::Note, "reusing microvm-x", &mut err);
        wrapper.speak(Kind::Warning, "audit row not written", &mut err);
        assert!(err.is_empty(), "the wrapper's notes and warnings stay off stderr: {}", String::from_utf8_lossy(&err));
        wrapper.speak(Kind::Line, "lost the VM: reopen the chat from the picker", &mut err);
        assert_eq!(String::from_utf8_lossy(&err), "ai-env-claude: lost the VM: reopen the chat from the picker\n");
        let cli = Speaker::new();
        let mut err = Vec::new();
        cli.speak(Kind::Warning, "audit row not written", &mut err);
        cli.speak(Kind::Note, "reusing microvm-x", &mut err);
        assert_eq!(String::from_utf8_lossy(&err), "ai-env: warning: audit row not written\nai-env: reusing microvm-x\n");
    }

    /// The fork gap (option B): an echo is another program's line as it is,
    /// on stderr for either voice (the wrapper's notes stay in its log), and
    /// the wrapper's own line after it is the last.
    #[test]
    fn an_echo_is_the_line_as_it_is_before_the_wrappers_last() {
        let miss = "No conversation found with session ID: 0199a1b2-0000-7000-8000-0000000012a3";
        for voice in [Voice::Cli, Voice::Wrapper] {
            assert_eq!(rendered(voice, Kind::Echo, miss), Some(miss.to_string()), "{voice:?}");
        }
        let wrapper = Speaker::new();
        wrapper.set(Voice::Wrapper);
        let mut err = Vec::new();
        wrapper.speak(Kind::Note, "refused before the pump", &mut err);
        wrapper.speak(Kind::Echo, miss, &mut err);
        wrapper.speak(Kind::Line, "refused before any Touch ID: nothing to resume; start a new chat", &mut err);
        let text = String::from_utf8_lossy(&err);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines, [miss, "ai-env-claude: refused before any Touch ID: nothing to resume; start a new chat"], "{text}");
        assert!(text.ends_with("start a new chat\n"), "the wrapper's line last: {text}");
    }
}
