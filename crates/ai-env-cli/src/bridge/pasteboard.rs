//! The clipboard of the deployer key's hand-over (S8 operators, `ai-env creds
//! deployer-key`): a value goes on the general pasteboard of this Mac only,
//! marked concealed, and is cleared again once it was pasted; nothing here
//! ever reads what the clipboard holds.
//!
//! Each operation is one child, `<osascript> -l JavaScript -e <script>`, run
//! with a 10 s timeout. `<osascript>` is [`OSASCRIPT`], absolute and never
//! looked up in PATH; debug builds run [`OSASCRIPT_KNOB`]'s value instead when
//! it is set (the tests' stand-in), release builds ignore it. The value
//! travels in the child's environment (`AI_ENV_PB_VALUE`), never in its argv,
//! and the child inherits neither the variables the age children lose nor
//! the `ai-env as` marker. The script marks the contents current-host-only
//! and concealed (`org.nspasteboard.ConcealedType`,
//! `org.nspasteboard.TransientType`) and prints the pasteboard's change
//! count; a later clear empties the pasteboard only while that count is
//! unchanged, so a copy made since is left alone. `pbcopy` is never a
//! fallback: when the clipboard cannot be set this way, nothing goes on it.
use crate::age_cmd::CHILD_ENV_REMOVED;
use crate::bridge::doctor::{capture, Captured};
use crate::commands::RUNNER_MARKER;
use crate::errors::{CliError, Result};
use crate::wire::redact::scrub;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The osascript the pasteboard runs: absolute, never looked up in PATH.
pub const OSASCRIPT: &str = "/usr/bin/osascript";
/// Debug builds only: the program to run in place of [`OSASCRIPT`] (the
/// tests' `tests/fakes/osascript.sh`). Release builds ignore it.
pub const OSASCRIPT_KNOB: &str = "AI_ENV_BRIDGE_LAB_OSASCRIPT";

/// How long one osascript may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The operation: `set`, `clear-if` or `clear`.
const OP: &str = "AI_ENV_PB_OP";
/// The value of `set`: in the child's environment only.
const VALUE: &str = "AI_ENV_PB_VALUE";
/// The change count `clear-if` compares (what `set` printed).
const COUNT: &str = "AI_ENV_PB_COUNT";

/// The JXA program. `set`: new contents for this Mac only
/// (`NSPasteboardContentsCurrentHostOnly`, 1), first the nspasteboard.org
/// markers that keep clipboard managers and history from recording it
/// (concealed, transient), then the value as plain text, so nothing that reads
/// the pasteboard while it is written sees the value unmarked; a write that is
/// refused empties the pasteboard and fails (nothing is placed); it prints the
/// change count. `clear-if` empties the pasteboard only while the change count
/// is the one given (`cleared`), else leaves it (`kept`); `clear` empties it
/// (`cleared`). It reads only the change count, never the contents.
pub const SCRIPT: &str = r"ObjC.import('AppKit');
var env = $.NSProcessInfo.processInfo.environment;
function get(name) {
  var v = env.objectForKey(name);
  return (v === undefined || v === null || v.isNil()) ? '' : ObjC.unwrap(v);
}
var op = get('AI_ENV_PB_OP');
var pb = $.NSPasteboard.generalPasteboard;
var out;
if (op === 'set') {
  var value = env.objectForKey('AI_ENV_PB_VALUE');
  if (value === undefined || value === null || value.isNil() || value.length === 0) {
    throw new Error('no value in AI_ENV_PB_VALUE');
  }
  pb.prepareForNewContentsWithOptions(1);
  if (!(pb.setStringForType('', 'org.nspasteboard.ConcealedType') && pb.setStringForType('', 'org.nspasteboard.TransientType') && pb.setStringForType(value, 'public.utf8-plain-text'))) {
    pb.clearContents;
    throw new Error('setString:forType: refused');
  }
  out = String(pb.changeCount);
} else if (op === 'clear-if') {
  if (String(pb.changeCount) === get('AI_ENV_PB_COUNT')) {
    pb.clearContents;
    out = 'cleared';
  } else {
    out = 'kept';
  }
} else if (op === 'clear') {
  pb.clearContents;
  out = 'cleared';
} else {
  throw new Error('unknown AI_ENV_PB_OP');
}
out;
";

/// The clear a signal handler can ask for ([`janitor`]): `/bin/sh` reads one
/// line from its stdin. The line `clear` runs `<osascript> -l JavaScript -e
/// <script>` (`$1`, `$2`) with [`clear`]'s environment and exits 0 once it
/// answered `cleared`, else 1; the end of its input (the hand-over is over,
/// or ai-env ended) exits 3 and clears nothing.
const JANITOR: &str = r#"IFS= read -r line || exit 3
[ "$line" = clear ] || exit 3
out=$("$1" -l JavaScript -e "$2") || exit 1
[ "$out" = cleared ]"#;

/// A value on the clipboard: the pasteboard's change count right after it
/// was placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    pub change_count: u64,
}

/// One operation of [`SCRIPT`].
enum Op<'a> {
    Set(&'a str),
    ClearIf(u64),
    Clear,
}

impl Op<'_> {
    fn word(&self) -> &'static str {
        match self {
            Op::Set(_) => "set",
            Op::ClearIf(_) => "clear-if",
            Op::Clear => "clear",
        }
    }
}

/// The knob's value (debug builds only; empty is unset).
#[cfg(debug_assertions)]
fn knob() -> Option<OsString> {
    std::env::var_os(OSASCRIPT_KNOB)
}

/// Release builds: no knob, whatever the environment says.
#[cfg(not(debug_assertions))]
fn knob() -> Option<OsString> {
    None
}

/// [`OSASCRIPT`], or in a debug build (`debug`) the knob's value when it is set.
fn program_of(debug: bool, knob: Option<OsString>) -> PathBuf {
    match knob.filter(|k| debug && !k.is_empty()) {
        Some(k) => PathBuf::from(k),
        None => PathBuf::from(OSASCRIPT),
    }
}

fn program() -> PathBuf {
    program_of(cfg!(debug_assertions), knob())
}

/// `<program> -l JavaScript -e SCRIPT` for `op`, in [`set_env`]'s
/// environment. The value is in the environment only: never Debug-format
/// this command.
fn command(program: &Path, op: &Op<'_>) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(["-l", "JavaScript", "-e", SCRIPT]);
    set_env(&mut cmd, op);
    cmd
}

/// The environment of a child for `op`: inherited, minus the age children's
/// credential variables and the `ai-env as` marker, plus the operation and
/// its operand.
fn set_env(cmd: &mut Command, op: &Op<'_>) {
    for name in CHILD_ENV_REMOVED.iter().chain(&[RUNNER_MARKER, OP, VALUE, COUNT]) {
        cmd.env_remove(name);
    }
    cmd.env(OP, op.word());
    match op {
        Op::Set(value) => {
            cmd.env(VALUE, value);
        }
        Op::ClearIf(count) => {
            cmd.env(COUNT, count.to_string());
        }
        Op::Clear => {}
    }
}

/// [`JANITOR`] with `program` as its osascript: stdin a pipe, stdout and
/// stderr discarded, a process group of its own.
fn janitor_command(program: &Path) -> Command {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", JANITOR, "ai-env-clipboard"]).arg(program).arg(SCRIPT);
    set_env(&mut cmd, &Op::Clear);
    cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
    cmd
}

/// A clear made ready before it may be needed, for a stop signal's handler,
/// which may only write a line and wait: it writes `clear\n` to the child's
/// stdin and waits for its exit (0: cleared), or closes the stdin to let it go
/// without clearing ([`JANITOR`]). The child runs the program [`clear`] runs, in
/// a process group of its own, so a Ctrl-C at the terminal reaches ai-env and
/// never it.
pub fn janitor() -> std::io::Result<Child> {
    janitor_with(&program())
}

/// [`janitor`] running `program` as the osascript.
pub(crate) fn janitor_with(program: &Path) -> std::io::Result<Child> {
    janitor_command(program).spawn()
}

/// What a failed osascript said: its first stderr line (scrubbed, at most 300
/// characters), else its exit.
fn failure(out: &Captured) -> String {
    match out.stderr.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(line) => scrub(line).chars().take(300).collect(),
        None => out.code.map_or_else(|| "osascript: killed by a signal".to_string(), |code| format!("osascript: exit {code}")),
    }
}

/// Run `op` with `program`: its stdout, trimmed, on success; else exit 1
/// naming osascript's first stderr line (a timeout or a missing program by
/// what `capture` says of it).
fn run(program: &Path, op: &Op<'_>) -> Result<String> {
    let out = capture(command(program, op), None, TIMEOUT).map_err(|e| CliError::Msg(scrub(&e).into_owned()))?;
    if !out.success {
        return Err(CliError::Msg(failure(&out)));
    }
    Ok(out.stdout.trim().to_string())
}

/// A change count: one or more ASCII digits.
fn count_of(answer: &str) -> Option<u64> {
    if answer.is_empty() || !answer.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    answer.parse().ok()
}

fn place_with(program: &Path, value: &str) -> Result<Placed> {
    let answer = run(program, &Op::Set(value))?;
    count_of(&answer).map(|change_count| Placed { change_count }).ok_or_else(|| CliError::Msg("osascript answered without a change count".into()))
}

fn clear_if_with(program: &Path, placed: &Placed) -> Result<bool> {
    match run(program, &Op::ClearIf(placed.change_count))?.as_str() {
        "cleared" => Ok(true),
        "kept" => Ok(false),
        _ => Err(CliError::Msg("osascript answered neither cleared nor kept".into())),
    }
}

fn clear_with(program: &Path) -> Result<()> {
    match run(program, &Op::Clear)?.as_str() {
        "cleared" => Ok(()),
        _ => Err(CliError::Msg("osascript did not answer cleared".into())),
    }
}

/// Put `value` on the clipboard, this Mac only and concealed.
pub fn place(value: &str) -> Result<Placed> {
    place_with(&program(), value)
}

/// Clear the clipboard unless something was copied since `placed`: `true`
/// when it was cleared, `false` when it was left as it is.
pub fn clear_if_unchanged(placed: &Placed) -> Result<bool> {
    clear_if_with(&program(), placed)
}

/// Clear the clipboard, whatever it holds.
pub fn clear() -> Result<()> {
    clear_with(&program())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(name, value)` of every variable `cmd` sets (`Some`) or removes (`None`).
    fn envs(cmd: &Command) -> Vec<(String, Option<String>)> {
        cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect()
    }

    fn set(e: &[(String, Option<String>)], name: &str) -> Option<String> {
        e.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.clone())
    }

    fn removed(e: &[(String, Option<String>)], name: &str) -> bool {
        e.iter().any(|(k, v)| k == name && v.is_none())
    }

    /// The value reaches osascript in its environment only; the child loses
    /// the credential variables and the marker; the script marks the contents
    /// this-Mac-only, concealed and transient, and never reads them.
    #[test]
    fn the_value_travels_only_in_the_environment() {
        let value = "a-value-of-this-test-0123";
        let cmd = command(Path::new(OSASCRIPT), &Op::Set(value));
        assert_eq!(cmd.get_program(), OSASCRIPT);
        let argv: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(argv, ["-l", "JavaScript", "-e", SCRIPT]);
        assert!(argv.iter().all(|a| !a.contains(value)), "the value is never in argv");
        let e = envs(&cmd);
        assert_eq!((set(&e, OP).as_deref(), set(&e, VALUE).as_deref()), (Some("set"), Some(value)));
        assert!(removed(&e, COUNT));
        for name in CHILD_ENV_REMOVED.iter().chain(&[RUNNER_MARKER]) {
            assert!(removed(&e, name), "{name} reaches osascript");
        }
        let e = envs(&command(Path::new(OSASCRIPT), &Op::ClearIf(101)));
        assert_eq!((set(&e, OP).as_deref(), set(&e, COUNT).as_deref()), (Some("clear-if"), Some("101")));
        assert!(removed(&e, VALUE), "an inherited value never reaches clear-if");
        let e = envs(&command(Path::new(OSASCRIPT), &Op::Clear));
        assert!(set(&e, OP).as_deref() == Some("clear") && removed(&e, VALUE) && removed(&e, COUNT));
        for want in [
            "ObjC.import('AppKit')",
            "$.NSProcessInfo.processInfo.environment",
            "prepareForNewContentsWithOptions(1)",
            "setStringForType(value, 'public.utf8-plain-text')",
            "setStringForType('', 'org.nspasteboard.ConcealedType')",
            "setStringForType('', 'org.nspasteboard.TransientType')",
            "'AI_ENV_PB_OP'",
            "'AI_ENV_PB_VALUE'",
            "'AI_ENV_PB_COUNT'",
            "String(pb.changeCount)",
            "pb.clearContents;",
        ] {
            assert!(SCRIPT.contains(want), "the script lacks {want}");
        }
        for never in ["stringForType", "dataForType", "propertyListForType", "readObjects", "pasteboardItems", "pbcopy", "pbpaste"] {
            assert!(!SCRIPT.contains(never), "the script reads the clipboard or shells out: {never}");
        }
        // The markers go first, the value last: whoever reads the pasteboard while
        // it is written never sees the value unmarked; a refused write empties it
        // again before the run fails.
        let at = |s: &str| SCRIPT.find(s).unwrap();
        assert!(at("prepareForNewContentsWithOptions(1)") < at("org.nspasteboard.ConcealedType"));
        assert!(at("org.nspasteboard.ConcealedType") < at("public.utf8-plain-text") && at("org.nspasteboard.TransientType") < at("public.utf8-plain-text"));
        assert!(SCRIPT.contains("pb.clearContents;\n    throw new Error('setString:forType: refused');"), "a refused write leaves nothing placed");
    }

    /// The program is the absolute osascript; only a debug build takes the knob.
    #[test]
    fn the_program_is_absolute_and_the_knob_is_for_debug_builds() {
        let knob = || Some(OsString::from("/tmp/the-tests/osascript"));
        assert!(Path::new(OSASCRIPT).is_absolute());
        assert_eq!(program_of(true, None), PathBuf::from(OSASCRIPT));
        assert_eq!(program_of(true, knob()), PathBuf::from("/tmp/the-tests/osascript"));
        assert_eq!(program_of(false, knob()), PathBuf::from(OSASCRIPT), "a release build ignores the knob");
        assert_eq!(program_of(true, Some(OsString::new())), PathBuf::from(OSASCRIPT), "empty is unset");
        assert_eq!(OSASCRIPT_KNOB, "AI_ENV_BRIDGE_LAB_OSASCRIPT");
    }

    /// tests/fakes/osascript.sh as `dir/name`, exporting `knobs` (the test
    /// process's own environment is never changed). macOS takes seconds over
    /// the first exec of a new file, which a 10 s osascript timeout must never
    /// pay: each directory gets one wrapper, run once (`--warm`, which runs
    /// nothing), and each fake is a hard link to it (no new file to check),
    /// its knobs in `<name>.knobs` beside it.
    fn fake(dir: &Path, name: &str, knobs: &[(&str, String)]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let wrapper = dir.join("osascript-wrapper");
        if !wrapper.exists() {
            let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/osascript.sh");
            std::fs::write(&wrapper, format!("#!/bin/sh\n[ \"${{1:-}}\" = --warm ] && exit 0\n. \"$0.knobs\"\nexec /bin/sh '{}' \"$@\"\n", src.display())).unwrap();
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(Command::new(&wrapper).arg("--warm").status().unwrap().success(), "{}", wrapper.display());
        }
        let exports: String = knobs.iter().map(|(k, v)| format!("export {k}='{v}'\n")).collect();
        let p = dir.join(name);
        std::fs::write(dir.join(format!("{name}.knobs")), exports).unwrap();
        std::fs::hard_link(&wrapper, &p).unwrap();
        p
    }

    /// Place, clear-if and clear read what osascript answers: the change count,
    /// `cleared` or `kept` (another copy came since); a failure is exit 1
    /// naming osascript's first stderr line, and nothing is ever printed of
    /// the value.
    #[test]
    fn place_and_clear_read_what_osascript_answers() {
        let d = tempfile::tempdir().unwrap();
        let (state, log) = (d.path().join("pb.state"), d.path().join("osa.log"));
        let knobs = vec![("FAKE_PB_STATE", state.display().to_string()), ("FAKE_OSA_LOG", log.display().to_string()), ("FAKE_PB_EXPECT_1", "first-value-0001".to_string())];
        let ok = fake(d.path(), "osascript", &knobs);
        let placed = place_with(&ok, "first-value-0001").unwrap();
        assert_eq!(placed, Placed { change_count: 101 });
        assert!(clear_if_with(&ok, &placed).unwrap(), "nothing was copied since");
        let mut touching = knobs.clone();
        touching.push(("FAKE_PB_TOUCH", "1".to_string()));
        let touched = fake(d.path(), "touched", &touching);
        let second = place_with(&touched, "second-value-0002").unwrap();
        assert_eq!(second, Placed { change_count: 102 });
        assert!(!clear_if_with(&touched, &second).unwrap(), "another copy came since: left alone");
        clear_with(&ok).unwrap();
        let logged = std::fs::read_to_string(&log).unwrap();
        assert_eq!(logged.lines().collect::<Vec<_>>(), ["set 1 match", "clear-if cleared", "set 2 unchecked", "clear-if kept", "clear cleared"]);
        for (failing, op) in [("1", "every"), ("set", "set"), ("clear-if", "clear-if"), ("clear", "clear")] {
            let mut k = knobs.clone();
            k.push(("FAKE_OSA_FAIL", failing.to_string()));
            let p = fake(d.path(), &format!("failing-{failing}"), &k);
            let refused = "execution error: Error: Error: setString:forType: refused (-2700)";
            let (a, b, c) = (place_with(&p, "x-value-0003").map(|_| ()), clear_if_with(&p, &placed).map(|_| ()), clear_with(&p));
            for (what, r) in [("set", a), ("clear-if", b), ("clear", c)] {
                let fails = op == "every" || op == what;
                match r {
                    Err(e) if fails => assert_eq!((e.exit_code(), e.to_string().as_str()), (1, refused), "{failing}: {what}"),
                    Ok(()) if !fails => {}
                    other => panic!("FAKE_OSA_FAIL={failing}, {what}: {:?}", other.map_err(|e| e.to_string())),
                }
            }
        }
        let e = place_with(&ok, "").unwrap_err();
        assert_eq!(e.to_string(), "execution error: Error: Error: no value in AI_ENV_PB_VALUE (-2700)");
        let missing = d.path().join("no-such-osascript");
        let e = place_with(&missing, "x-value-0004").unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().starts_with(&missing.display().to_string()), "{e}");
        assert!(!std::fs::read_to_string(&log).unwrap().contains("value-000"), "the log holds no value");
        assert_eq!(count_of("17"), Some(17));
        for odd in ["", "x", "1 2", "-1", "99999999999999999999999"] {
            assert_eq!(count_of(odd), None, "{odd:?}");
        }
    }

    /// The stop handler's clear: `/bin/sh` in a process group of its own, with
    /// [`clear`]'s environment (no key, no marker, no value); it runs osascript
    /// only once it read `clear`, its exit saying whether osascript answered
    /// `cleared`; the end of its input lets it go unasked.
    #[test]
    fn the_janitor_clears_only_when_asked() {
        use std::io::Write as _;
        let cmd = janitor_command(Path::new(OSASCRIPT));
        assert_eq!(cmd.get_program(), "/bin/sh");
        let argv: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(argv, ["-c", JANITOR, "ai-env-clipboard", OSASCRIPT, SCRIPT]);
        let e = envs(&cmd);
        assert!(set(&e, OP).as_deref() == Some("clear") && removed(&e, VALUE) && removed(&e, COUNT));
        for name in CHILD_ENV_REMOVED.iter().chain(&[RUNNER_MARKER]) {
            assert!(removed(&e, name), "{name} reaches the janitor");
        }
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("osa.log");
        let logged = || std::fs::read_to_string(&log).unwrap_or_default();
        let ok = fake(d.path(), "osascript", &[("FAKE_OSA_LOG", log.display().to_string())]);
        // Let go unasked: nothing ran.
        let mut j = janitor_with(&ok).unwrap();
        let pid = i32::try_from(j.id()).unwrap();
        // SAFETY: getpgid(2) of a child of this process that is not reaped yet.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid, "a process group of its own");
        drop(j.stdin.take());
        assert_eq!(j.wait().unwrap().code(), Some(3));
        assert_eq!(logged(), "");
        // Asked: one clear, exit 0.
        let mut j = janitor_with(&ok).unwrap();
        j.stdin.take().unwrap().write_all(b"clear\n").unwrap();
        assert_eq!(j.wait().unwrap().code(), Some(0));
        assert_eq!(logged(), "clear cleared\n");
        // osascript refuses: exit 1.
        let failing = fake(d.path(), "failing", &[("FAKE_OSA_LOG", log.display().to_string()), ("FAKE_OSA_FAIL", "clear".to_string())]);
        let mut j = janitor_with(&failing).unwrap();
        j.stdin.take().unwrap().write_all(b"clear\n").unwrap();
        assert_eq!(j.wait().unwrap().code(), Some(1));
        assert_eq!(logged(), "clear cleared\nfail clear\n");
    }
}
