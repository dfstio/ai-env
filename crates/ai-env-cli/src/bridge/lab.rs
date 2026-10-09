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

/// The S4 knob names (and S6's agent address, S7's unseal budget), for the
/// banner and the test harnesses' scrub lists.
pub const VM_KNOBS: [&str; 5] = ["AI_ENV_BRIDGE_LAB_FAKE_API", "AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "AI_ENV_BRIDGE_LAB_BACKOFF_MS", "AI_ENV_BRIDGE_LAB_AGENT_ADDR", crate::bridge::pump::UNSEAL_TIMEOUT_KNOB];

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
    /// `AI_ENV_BRIDGE_LAB_AGENT_ADDR=127.0.0.1:<port>` (S6 D4): `/agent` is
    /// dialed in plain `ws://` at this loopback address (a test's fake
    /// endpoint) instead of `wss://<endpoint>:443`. Honoured only together
    /// with the fake API; see [`VmKnobs::agent_addr`].
    pub agent_addr: Option<String>,
    /// `AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS=<n>` (S7): the budget of every
    /// unseal a credentialed `vm` or `lab` command makes, in place of
    /// `[creds].unseal_timeout_s` (whose range starts at 10 s), as the
    /// wrapper's own knob of that name does for `local-scratch`: a deadline
    /// test reaches its deadline in a second or two. Whole seconds read best
    /// (the deadline and the countdown say seconds).
    pub unseal_timeout: Option<Duration>,
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
        if self.agent_addr.is_some() {
            out.push(VM_KNOBS[3]);
        }
        if self.unseal_timeout.is_some() {
            out.push(VM_KNOBS[4]);
        }
        out
    }

    /// The validated agent address: `Ok(None)` when unset; an error when set
    /// without the fake API (the real endpoint is never dialed in plain text)
    /// or when not a loopback `ip:port`.
    pub fn agent_addr(&self) -> Result<Option<std::net::SocketAddr>, String> {
        let Some(raw) = &self.agent_addr else {
            return Ok(None);
        };
        if self.fake_api.is_none() {
            return Err(format!("{} needs {} (it never applies to the real service)", VM_KNOBS[3], VM_KNOBS[0]));
        }
        match raw.trim().parse::<std::net::SocketAddr>() {
            Ok(a) if a.ip().is_loopback() && a.port() != 0 => Ok(Some(a)),
            _ => Err(format!("{}={raw:?}: expected a loopback ip:port", VM_KNOBS[3])),
        }
    }

    /// Is the platform emulated: the fake API with a valid agent address, so
    /// `/agent` reaches a test's shim behind a fake endpoint that also plays
    /// the platform's hooks (`tests/common/fake_endpoint.rs`)? Only S7's
    /// credential probes take that for the service (`vm::lab`); every other
    /// live probe still refuses the fake. Never true in release builds, whose
    /// knobs are all off.
    #[must_use]
    pub fn emulated_platform(&self) -> bool {
        self.fake_api.is_some() && matches!(self.agent_addr(), Ok(Some(_)))
    }
}

/// Pure parser over the three S4 raw values (unset = `None`); anything
/// unparseable is off. The S6 agent address and the S7 unseal budget are set
/// by [`vm_knobs`].
#[must_use]
pub fn parse_vm_knobs(fake_api: Option<&str>, unseal: Option<&str>, backoff_ms: Option<&str>) -> VmKnobs {
    VmKnobs {
        fake_api: fake_api.map(str::trim).filter(|p| !p.is_empty()).map(std::path::PathBuf::from),
        fake_api_unseal: unseal.map(str::trim) == Some("1"),
        backoff_ms: backoff_ms.and_then(|v| v.trim().parse::<u64>().ok()).filter(|ms| *ms > 0),
        agent_addr: None,
        unseal_timeout: None,
    }
}

/// The VM knobs from the environment (debug builds only).
#[cfg(debug_assertions)]
#[must_use]
pub fn vm_knobs() -> VmKnobs {
    let get = |k: &str| std::env::var(k).ok();
    VmKnobs {
        agent_addr: get(VM_KNOBS[3]).filter(|v| !v.trim().is_empty()),
        unseal_timeout: crate::bridge::pump::parse_ms_knob(get(VM_KNOBS[4]).as_deref()),
        ..parse_vm_knobs(get(VM_KNOBS[0]).as_deref(), get(VM_KNOBS[1]).as_deref(), get(VM_KNOBS[2]).as_deref())
    }
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
        assert_eq!(k.active(), VM_KNOBS[..3].to_vec());
        assert_eq!(parse_vm_knobs(Some(" "), Some("yes"), Some("0")), VmKnobs::default(), "blank, garbage and 0 are off");
    }

    #[test]
    fn agent_addr_needs_the_fake_api_and_loopback() {
        let with = |fake: bool, addr: &str| VmKnobs { fake_api: fake.then(|| std::path::PathBuf::from("/f.json")), agent_addr: Some(addr.to_string()), ..VmKnobs::default() };
        assert_eq!(VmKnobs::default().agent_addr(), Ok(None));
        assert_eq!(with(true, "127.0.0.1:18080").agent_addr(), Ok(Some("127.0.0.1:18080".parse().unwrap())));
        assert_eq!(with(true, "[::1]:18080").agent_addr(), Ok(Some("[::1]:18080".parse().unwrap())));
        assert!(with(false, "127.0.0.1:18080").agent_addr().unwrap_err().contains("needs AI_ENV_BRIDGE_LAB_FAKE_API"), "never against the real service");
        for bad in ["10.0.0.5:18080", "example.com:80", "127.0.0.1", "127.0.0.1:0", "garbage"] {
            assert!(with(true, bad).agent_addr().is_err(), "{bad}");
        }
        assert_eq!(with(true, "127.0.0.1:1").active(), vec![VM_KNOBS[0], VM_KNOBS[3]]);
    }

    /// The S7 unseal budget is the wrapper's knob of that name, read as
    /// every `_MS` knob is, and announced when set: a `vm` command run with
    /// it never passes for the real service's budget.
    #[test]
    fn the_unseal_budget_knob_is_the_wrappers_and_is_announced() {
        assert_eq!(VM_KNOBS[4], crate::bridge::pump::UNSEAL_TIMEOUT_KNOB);
        assert_eq!(crate::bridge::pump::parse_ms_knob(Some("2000")), Some(Duration::from_secs(2)));
        let k = VmKnobs { unseal_timeout: Some(Duration::from_secs(2)), ..VmKnobs::default() };
        assert_eq!(k.active(), vec![VM_KNOBS[4]]);
        assert_eq!(parse_vm_knobs(None, None, None).unseal_timeout, None, "set by vm_knobs alone");
    }

    /// The emulated platform takes the fake API and a valid agent address
    /// together: neither alone, nor an address the knob refuses.
    #[test]
    fn the_platform_is_emulated_only_with_the_fake_api_and_a_valid_agent_addr() {
        let knobs = |fake: bool, addr: Option<&str>| VmKnobs { fake_api: fake.then(|| std::path::PathBuf::from("/f.json")), agent_addr: addr.map(str::to_string), ..VmKnobs::default() };
        assert!(knobs(true, Some("127.0.0.1:18080")).emulated_platform());
        assert!(!knobs(true, None).emulated_platform(), "the fake alone has no shim behind it");
        assert!(!knobs(false, Some("127.0.0.1:18080")).emulated_platform(), "the address alone is never the real service's");
        assert!(!knobs(true, Some("10.0.0.5:18080")).emulated_platform(), "not loopback");
        assert!(!VmKnobs::default().emulated_platform(), "release builds: every knob off");
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
