//! Lab knobs for the wrapper's failure paths. Every knob is compiled out of
//! release builds (`cfg(debug_assertions)` at function level), so the
//! installed release wrapper cannot be steered by an environment variable.
//! S1 shipped the pre-exec exit knob; S2 adds the pump-stage knobs: the
//! `:after-init` form of the exit knob, ignore-EOF, stdout noise, a delayed
//! initialize response and a short replay deadline.
use std::time::Duration;

/// The suffix that turns `AI_ENV_BRIDGE_LAB_EXIT` into the S2 pump form.
pub const AFTER_INIT_SUFFIX: &str = ":after-init";

/// `AI_ENV_BRIDGE_LAB_EXIT="<code>:<stderr>"`: after the census and before
/// exec, print `stderr` and exit with `code`. The S2 form with a trailing
/// `:after-init` is ignored here (see [`exit_after_init`]).
#[cfg(debug_assertions)]
#[must_use]
pub fn exit_knob() -> Option<(i32, String)> {
    parse_exit_knob(&std::env::var("AI_ENV_BRIDGE_LAB_EXIT").ok()?)
}

/// Release builds: no knob, whatever the environment says.
#[cfg(not(debug_assertions))]
#[must_use]
pub fn exit_knob() -> Option<(i32, String)> {
    None
}

/// Pure parser for `<code>:<message>`; the message may itself contain `:`.
/// A trailing `:after-init` is the pump form and yields `None` here.
#[must_use]
pub fn parse_exit_knob(value: &str) -> Option<(i32, String)> {
    if value.ends_with(AFTER_INIT_SUFFIX) {
        return None;
    }
    let (code, message) = value.split_once(':')?;
    let code = code.trim().parse::<i32>().ok()?;
    Some((code, message.to_string()))
}

/// `AI_ENV_BRIDGE_LAB_EXIT="<code>:<stderr>:after-init"`: the pump, after the
/// first forwarded `system/init`, terminates the child and exits with `code`,
/// `stderr` being the last line on stderr.
#[cfg(debug_assertions)]
#[must_use]
pub fn exit_after_init() -> Option<(i32, String)> {
    parse_after_init_knob(&std::env::var("AI_ENV_BRIDGE_LAB_EXIT").ok()?)
}

/// Release builds: no knob.
#[cfg(not(debug_assertions))]
#[must_use]
pub fn exit_after_init() -> Option<(i32, String)> {
    None
}

/// Pure parser for `<code>:<message>:after-init`; only that form parses (the
/// message may contain `:`).
#[must_use]
pub fn parse_after_init_knob(value: &str) -> Option<(i32, String)> {
    let body = value.strip_suffix(AFTER_INIT_SUFFIX)?;
    let (code, message) = body.split_once(':')?;
    let code = code.trim().parse::<i32>().ok()?;
    Some((code, message.to_string()))
}

/// The pump-stage knobs other than the exit knob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PumpKnobs {
    /// `AI_ENV_BRIDGE_LAB_IGNORE_EOF`: 0 off; 1 ignore host stdin EOF (SIGTERM
    /// still honoured, so the end row measures the extension's EOF→SIGTERM
    /// rung); 2 ignore EOF and SIGTERM (the extension's SIGKILL ends it).
    pub ignore_eof: u8,
    /// `AI_ENV_BRIDGE_LAB_STDOUT_NOISE=1`: after the first init, log `hello`
    /// and print it on stderr — never on stdout.
    pub stdout_noise: bool,
    /// `AI_ENV_BRIDGE_LAB_DELAY_INIT_MS=<n>`: hold the first child's stdout
    /// for `n` ms after spawn (initialize response included).
    pub delay_init: Option<Duration>,
    /// `AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS=<n>`: the respawn replay deadline
    /// (default 15 s) — lets the timeout path be tested in well under a second.
    pub replay_deadline: Option<Duration>,
}

/// Pure parser over the four raw values (unset = `None`). Anything
/// unparseable is treated as unset: a lab knob never breaks a session.
#[must_use]
pub fn parse_pump_knobs(ignore_eof: Option<&str>, noise: Option<&str>, delay_ms: Option<&str>, replay_ms: Option<&str>) -> PumpKnobs {
    let ms = |v: Option<&str>| v.and_then(|v| v.trim().parse::<u64>().ok()).filter(|ms| *ms > 0).map(Duration::from_millis);
    PumpKnobs {
        ignore_eof: match ignore_eof.map(str::trim) {
            Some("1") => 1,
            Some("2") => 2,
            _ => 0,
        },
        stdout_noise: noise.map(str::trim) == Some("1"),
        delay_init: ms(delay_ms),
        replay_deadline: ms(replay_ms),
    }
}

/// The pump knobs from the environment (debug builds only).
#[cfg(debug_assertions)]
#[must_use]
pub fn pump_knobs() -> PumpKnobs {
    let get = |k: &str| std::env::var(k).ok();
    parse_pump_knobs(
        get("AI_ENV_BRIDGE_LAB_IGNORE_EOF").as_deref(),
        get("AI_ENV_BRIDGE_LAB_STDOUT_NOISE").as_deref(),
        get("AI_ENV_BRIDGE_LAB_DELAY_INIT_MS").as_deref(),
        get("AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS").as_deref(),
    )
}

/// Release builds: every knob off.
#[cfg(not(debug_assertions))]
#[must_use]
pub fn pump_knobs() -> PumpKnobs {
    PumpKnobs::default()
}

// ---- S4: `ai-env vm` / `lab` knobs ---------------------------------------------------

/// The S4 knob names, for the banner and the test harnesses' scrub lists.
pub const VM_KNOBS: [&str; 3] = ["AI_ENV_BRIDGE_LAB_FAKE_API", "AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "AI_ENV_BRIDGE_LAB_BACKOFF_MS"];

/// The S4 knobs `ai-env vm` and `ai-env lab` honour (debug builds only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmKnobs {
    /// `AI_ENV_BRIDGE_LAB_FAKE_API=<file.json>`: the control plane AND the
    /// endpoint are `vm::fake_file::FileFakeMicrovmApi` over this file (state
    /// shared by processes under `flock(<file>.lock)`); no SDK, no network.
    pub fake_api: Option<std::path::PathBuf>,
    /// `AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL=1`: with the fake API, still unseal
    /// `credentials/aws.env` (tests of the container path with a fake age).
    pub fake_api_unseal: bool,
    /// `AI_ENV_BRIDGE_LAB_BACKOFF_MS=<n>`: every poll step and budget scaled
    /// from 1 s to `n` ms (the process-level tests run in milliseconds).
    pub backoff_ms: Option<u64>,
}

impl VmKnobs {
    /// The names of the active knobs (empty when none): an active knob is
    /// announced on stderr and marks every `--json` record `"backend":"fake"`
    /// (with the fake API) or `"backend":"sdk+knobs"` (any other knob).
    #[must_use]
    pub fn active(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.fake_api.is_some() {
            out.push(VM_KNOBS[0]);
        }
        if self.fake_api_unseal {
            out.push(VM_KNOBS[1]);
        }
        if self.backoff_ms.is_some() {
            out.push(VM_KNOBS[2]);
        }
        out
    }
}

/// Pure parser over the three raw values (unset = `None`); anything
/// unparseable is off.
#[must_use]
pub fn parse_vm_knobs(fake_api: Option<&str>, unseal: Option<&str>, backoff_ms: Option<&str>) -> VmKnobs {
    VmKnobs {
        fake_api: fake_api.map(str::trim).filter(|p| !p.is_empty()).map(std::path::PathBuf::from),
        fake_api_unseal: unseal.map(str::trim) == Some("1"),
        backoff_ms: backoff_ms.and_then(|v| v.trim().parse::<u64>().ok()).filter(|ms| *ms > 0),
    }
}

/// The S4 knobs from the environment (debug builds only).
#[cfg(debug_assertions)]
#[must_use]
pub fn vm_knobs() -> VmKnobs {
    let get = |k: &str| std::env::var(k).ok();
    parse_vm_knobs(get(VM_KNOBS[0]).as_deref(), get(VM_KNOBS[1]).as_deref(), get(VM_KNOBS[2]).as_deref())
}

/// Release builds: every knob off, whatever the environment says.
#[cfg(not(debug_assertions))]
#[must_use]
pub fn vm_knobs() -> VmKnobs {
    VmKnobs::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_code_and_message() {
        assert_eq!(parse_exit_knob("3:boom"), Some((3, "boom".to_string())));
        assert_eq!(parse_exit_knob("0:"), Some((0, String::new())));
        assert_eq!(parse_exit_knob("7:a:b"), Some((7, "a:b".to_string())), "the message may contain colons");
    }

    #[test]
    fn rejects_the_s2_form_and_garbage() {
        assert_eq!(parse_exit_knob("3:boom:after-init"), None);
        assert_eq!(parse_exit_knob("x:boom"), None);
        assert_eq!(parse_exit_knob("3"), None);
        assert_eq!(parse_exit_knob(""), None);
    }

    #[test]
    fn after_init_form_parses_only_with_the_suffix() {
        assert_eq!(parse_after_init_knob("3:boom:after-init"), Some((3, "boom".to_string())));
        assert_eq!(parse_after_init_knob("3:a:b:after-init"), Some((3, "a:b".to_string())), "colons in the message");
        assert_eq!(parse_after_init_knob("3::after-init"), Some((3, String::new())));
        assert_eq!(parse_after_init_knob("3:boom"), None, "the pre-exec form is not the pump form");
        assert_eq!(parse_after_init_knob("x:boom:after-init"), None);
        assert_eq!(parse_after_init_knob(":after-init"), None);
        // The two parsers never both fire on one value.
        for v in ["3:boom", "3:boom:after-init", "7:a:b", "0:"] {
            assert!(!(parse_exit_knob(v).is_some() && parse_after_init_knob(v).is_some()), "{v}");
        }
    }

    #[test]
    fn pump_knobs_parse_and_default() {
        assert_eq!(parse_pump_knobs(None, None, None, None), PumpKnobs::default());
        let k = parse_pump_knobs(Some("1"), Some("1"), Some("300"), Some("500"));
        assert_eq!(k, PumpKnobs { ignore_eof: 1, stdout_noise: true, delay_init: Some(Duration::from_millis(300)), replay_deadline: Some(Duration::from_millis(500)) });
        assert_eq!(parse_pump_knobs(Some("2"), None, None, None).ignore_eof, 2);
        assert_eq!(parse_pump_knobs(Some("yes"), Some("true"), Some("-5"), Some("x")), PumpKnobs::default(), "garbage is off");
        assert_eq!(parse_pump_knobs(None, None, Some("0"), Some("0")), PumpKnobs::default(), "0 ms is no knob");
    }

    #[test]
    fn vm_knobs_parse_and_default() {
        assert_eq!(parse_vm_knobs(None, None, None), VmKnobs::default());
        assert!(VmKnobs::default().active().is_empty());
        let k = parse_vm_knobs(Some("/tmp/f.json"), Some("1"), Some("2"));
        assert_eq!(k.fake_api.as_deref(), Some(std::path::Path::new("/tmp/f.json")));
        assert!(k.fake_api_unseal);
        assert_eq!(k.backoff_ms, Some(2));
        assert_eq!(k.active(), VM_KNOBS.to_vec());
        assert_eq!(parse_vm_knobs(Some(" "), Some("yes"), Some("0")), VmKnobs::default(), "blank, garbage and 0 are off");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn knob_reads_the_environment_in_debug_builds() {
        // The variable is read, not mutated: an unset variable yields None.
        // Setting it is left to the wrapper integration tests, which spawn a
        // fresh process (the process environment is shared by every test).
        if std::env::var_os("AI_ENV_BRIDGE_LAB_EXIT").is_none() {
            assert_eq!(exit_knob(), None);
            assert_eq!(exit_after_init(), None);
        }
    }
}
