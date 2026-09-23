//! Lab knobs for the wrapper's failure paths. Every knob is compiled out of
//! release builds (`cfg(debug_assertions)` at function level), so the
//! installed release wrapper cannot be steered by an environment variable.
//! S1 ships only the pre-exec exit knob; the pump-stage knobs
//! (`:after-init`, ignore-EOF, stdout noise, delayed init) arrive with S2.

/// `AI_ENV_BRIDGE_LAB_EXIT="<code>:<stderr>"`: after the census and before
/// exec, print `stderr` and exit with `code`. The S2 form with a trailing
/// `:after-init` is ignored here.
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
/// A trailing `:after-init` is the S2 form and yields `None` in S1.
#[must_use]
pub fn parse_exit_knob(value: &str) -> Option<(i32, String)> {
    if value.ends_with(":after-init") {
        return None;
    }
    let (code, message) = value.split_once(':')?;
    let code = code.trim().parse::<i32>().ok()?;
    Some((code, message.to_string()))
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

    #[cfg(debug_assertions)]
    #[test]
    fn knob_reads_the_environment_in_debug_builds() {
        // The variable is read, not mutated: an unset variable yields None.
        // Setting it is left to the wrapper integration tests, which spawn a
        // fresh process (the process environment is shared by every test).
        if std::env::var_os("AI_ENV_BRIDGE_LAB_EXIT").is_none() {
            assert_eq!(exit_knob(), None);
        }
    }
}
