//! The environment a remote session's spawn gets (S8 L4): the
//! `[wrapper].env_forward` and `env_extra` names present in Cursor's
//! environment, minus every name `vm exec --env` refuses; the wrapper's own
//! names (telemetry, autoupdater, claude.ai MCP servers, artifacts off); the
//! proxy variables first on a vpc VM. With `remote::session_grace`, the
//! spawn's detach grace. Built in S8 wave 1 (W2).
//!
//! [`session_env`] is P0's template (no AWS, no Touch ID): a configured name
//! the rules refuse is the session's failure (exit 9, the name named, never
//! a value), so a credential-shaped name in `env_extra` never travels by
//! accident. The proxy variables come at P4 (`agent::exec::spawn_env`, from
//! the VM's row), ahead of these: the rules refuse their names here.
//!
//! S12 (R2): the default `[wrapper].env_forward` also carries the extension's
//! `CLAUDE_CODE_QUESTION_PREVIEW_FORMAT` and `CLAUDE_CODE_SDK_READS_SESSION_STATE`
//! (an explicit list keeps its own); a name of [`HOST_REFRESH_NAMES`] in
//! either list refuses the session (R2-3: exit 9), since the wrapper answers
//! a remote CLI's credential refreshes itself, with no token.
//!
//! S13 (A6): the default list also carries extension 2.1.312's
//! `CLAUDE_CODE_EMIT_USER_PROMPT_SUBMIT_HOOK_EVENTS`; its
//! `CLAUDE_CODE_SDK_READS_STARTUP_MARKS` and `CLAUDE_CODE_STARTUP_FAILURE_RESULTS`
//! are reviewed (`drift::ENV_REVIEWED`), never forwarded by default, and a list
//! may still name them.
use crate::bridge::agent::exec::{is_env_name, is_proxy_name, refused_name, PROXY_VARS};
use crate::bridge::config::BridgeConfig;
use crate::wire::frame::ENV_MAX_ENTRIES;
use std::collections::BTreeMap;
use std::ffi::OsString;

/// The names the wrapper sets itself, over any forwarded value (L4): the
/// CLI's autoupdater, the claude.ai MCP servers, artifacts, and the
/// telemetry and error reports the egress allowlist would refuse anyway
/// (S7 B9 saw them denied by the proxy).
pub const WRAPPER_NAMES: [(&str, &str); 5] = [("DISABLE_AUTOUPDATER", "1"), ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"), ("CLAUDE_CODE_DISABLE_ARTIFACT", "1"), ("DISABLE_TELEMETRY", "1"), ("DISABLE_ERROR_REPORTING", "1")];

/// Set too when `[egress].disable_nonessential` (the default).
pub const NONESSENTIAL: (&str, &str) = ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");

/// What `[wrapper].strip_debug` keeps from the VM (as it strips `--debug`).
const DEBUG_NAME: &str = "DEBUG";

/// The CLI's projects-directory override (honoured with `CLAUDE_CONFIG_DIR`
/// set, as the shim sets it): a remote session's transcript stays under the
/// slug of the workspace's path, the one the mirror writes and Cursor's
/// picker reads, so a session never forwards it.
pub const PROJECT_DIR_NAME: &str = "CLAUDE_CODE_PROJECT_DIR_NAME";

/// S12 (R2): the names that tell the CLI its host refreshes its credentials: `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH`
/// (the extension's SDK sets it only for a host that passes a `getOAuthToken` callback) and
/// `CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH` (`getHostAuthToken`). A remote session never carries either: the wrapper
/// answers a remote CLI's `oauth_token_refresh` and `host_auth_token_refresh` itself, with no token
/// (pump.rs:2166-2178), and Tier B, which would answer them, is not built. Refused in `[wrapper]`, any case.
pub const HOST_REFRESH_NAMES: [&str; 2] = ["CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH", "CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH"];

/// The session's environment before the proxy variables (L4), from
/// `ext_env` (Cursor's: the wrapper's own environment): each name of
/// `[wrapper].env_forward`, then `env_extra`, once, when present and valid
/// UTF-8 (`DEBUG` only with `strip_debug = false`); then the wrapper's names
/// ([`WRAPPER_NAMES`], [`NONESSENTIAL`] with `[egress].disable_nonessential`)
/// over any forwarded value. `Err` names the first configured name that is
/// not a variable name or that `vm exec --env` refuses (`AWS_*`, a TOKEN,
/// KEY, SECRET or PASSWORD name, `CLAUDECODE`, `NODE_OPTIONS`, the shim's
/// `HOME`, `PATH` and `CLAUDE_CONFIG_DIR`, a proxy variable), or
/// [`PROJECT_DIR_NAME`], or (S12, R2-3) a name of [`HOST_REFRESH_NAMES`] in
/// any case, or more variables than a spawn takes beside the six proxy ones;
/// it never holds a value. The refresh names' refusal puts its reason in
/// parentheses right after the name, so the line's scrub (`remote::part`:
/// a key-shaped name followed by `:` masks the rest) keeps it whole.
pub fn session_env(cfg: &BridgeConfig, ext_env: &dyn Fn(&str) -> Option<OsString>) -> Result<BTreeMap<String, String>, String> {
    let w = &cfg.wrapper;
    let mut env = BTreeMap::new();
    let configured = w.env_forward.iter().map(|n| ("env_forward", n)).chain(w.env_extra.iter().map(|n| ("env_extra", n)));
    for (key, name) in configured {
        if !is_env_name(name) {
            return Err(format!("[wrapper].{key} holds {:?}: not a variable name ([A-Za-z_][A-Za-z0-9_]*)", crate::wire::redact::scrub(name)));
        }
        if let Some(why) = refused_name(name) {
            return Err(format!("[wrapper].{key} names {name}: {why}; remove it from bridge.toml"));
        }
        if is_proxy_name(name) {
            return Err(format!("[wrapper].{key} names {name}: ai-env sets the six proxy variables itself on vpc VMs; remove it from bridge.toml"));
        }
        if name == PROJECT_DIR_NAME {
            return Err(format!("[wrapper].{key} names {name}: a remote session keeps its transcript under the workspace's own project, where the mirror and the picker read it; remove it from bridge.toml"));
        }
        if HOST_REFRESH_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            return Err(format!("[wrapper].{key} names {name} (the wrapper answers a remote CLI's refreshes with no token); remove it from bridge.toml"));
        }
        if w.strip_debug && name.eq_ignore_ascii_case(DEBUG_NAME) {
            tracing::info!("[wrapper].{key} names {name}: kept from the VM (strip_debug)");
            continue;
        }
        match ext_env(name).map(OsString::into_string) {
            Some(Ok(value)) => {
                env.insert(name.clone(), value);
            }
            Some(Err(_)) => tracing::warn!("{name} is not valid UTF-8: not forwarded to the VM"),
            None => {}
        }
    }
    let nonessential = cfg.egress.disable_nonessential.then_some(NONESSENTIAL);
    for (name, value) in WRAPPER_NAMES.into_iter().chain(nonessential) {
        env.insert(name.to_string(), value.to_string());
    }
    if env.len() + PROXY_VARS > ENV_MAX_ENTRIES {
        return Err(format!("[wrapper].env_forward and env_extra make {} variables with the wrapper's own (at most {} beside the {PROXY_VARS} proxy variables)", env.len(), ENV_MAX_ENTRIES - PROXY_VARS));
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> BridgeConfig {
        BridgeConfig::parse(toml).unwrap()
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs.iter().map(|(k, v)| ((*k).to_string(), OsString::from(v))).collect();
        move |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    /// L4 with the defaults: the allowlisted names Cursor set, nothing else
    /// of its environment (a token, an AWS key, its own HOME and PATH), and
    /// the wrapper's six names, which win over a forwarded value. S12 (R2-1):
    /// the extension's two names cross with Cursor's values; neither refresh
    /// name does (R2-4: no list configures them). S13 (A6): of extension
    /// 2.1.312's three, `CLAUDE_CODE_EMIT_USER_PROMPT_SUBMIT_HOOK_EVENTS`
    /// crosses with Cursor's value; `CLAUDE_CODE_SDK_READS_STARTUP_MARKS` and
    /// `CLAUDE_CODE_STARTUP_FAILURE_RESULTS` do not (reviewed, never forwarded by default).
    #[test]
    fn the_vm_env_is_the_allowlist_plus_the_wrapper_names() {
        let token = format!("{}-{}-{}", "sk", "ant", "x".repeat(40));
        let ext = env_of(&[
            ("CLAUDE_CODE_ENTRYPOINT", "claude-vscode"),
            ("LANG", "en_US.UTF-8"),
            ("TERM", "xterm-256color"),
            ("CLAUDE_CODE_QUESTION_PREVIEW_FORMAT", "markdown"),
            ("CLAUDE_CODE_SDK_READS_SESSION_STATE", "1"),
            ("CLAUDE_CODE_EMIT_USER_PROMPT_SUBMIT_HOOK_EVENTS", "1"),
            ("CLAUDE_CODE_SDK_READS_STARTUP_MARKS", "1"),
            ("CLAUDE_CODE_STARTUP_FAILURE_RESULTS", "1"),
            ("CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH", "1"),
            ("CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH", "1"),
            ("CLAUDE_CODE_OAUTH_TOKEN", &token),
            ("AWS_SECRET_ACCESS_KEY", "s"),
            ("HOME", "/Users/mike"),
            ("PATH", "/usr/bin"),
            ("DEBUG", "1"),
            ("DISABLE_TELEMETRY", "0"),
        ]);
        let env = session_env(&BridgeConfig::default(), &ext).unwrap();
        let want: BTreeMap<String, String> = [
            ("CLAUDE_CODE_ENTRYPOINT", "claude-vscode"),
            ("LANG", "en_US.UTF-8"),
            ("TERM", "xterm-256color"),
            ("CLAUDE_CODE_QUESTION_PREVIEW_FORMAT", "markdown"),
            ("CLAUDE_CODE_SDK_READS_SESSION_STATE", "1"),
            ("CLAUDE_CODE_EMIT_USER_PROMPT_SUBMIT_HOOK_EVENTS", "1"),
            ("DISABLE_AUTOUPDATER", "1"),
            ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
            ("CLAUDE_CODE_DISABLE_ARTIFACT", "1"),
            ("DISABLE_TELEMETRY", "1"),
            ("DISABLE_ERROR_REPORTING", "1"),
            ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
        assert_eq!(env, want);
        let quiet = cfg("[egress]\ndisable_nonessential = false\n");
        assert!(!session_env(&quiet, &ext).unwrap().contains_key("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"), "only with [egress].disable_nonessential");
    }

    /// `env_extra` forwards what it names; `DEBUG` crosses only with
    /// `strip_debug = false`; a name not set, or not UTF-8, is left out.
    #[test]
    fn env_extra_forwards_and_debug_follows_strip_debug() {
        use std::os::unix::ffi::OsStringExt;
        let raw = |k: &str| match k {
            "MY_FLAG" => Some(OsString::from("on")),
            "DEBUG" => Some(OsString::from("*")),
            "NOT_UTF8" => Some(OsString::from_vec(vec![0xff, 0xfe])),
            _ => None,
        };
        let env = session_env(&cfg("[wrapper]\nenv_extra = [\"MY_FLAG\", \"DEBUG\", \"NOT_UTF8\", \"UNSET\"]\n"), &raw).unwrap();
        assert_eq!(env.get("MY_FLAG").map(String::as_str), Some("on"));
        assert!(!env.contains_key("DEBUG") && !env.contains_key("NOT_UTF8") && !env.contains_key("UNSET"), "{env:?}");
        let env = session_env(&cfg("[wrapper]\nstrip_debug = false\nenv_extra = [\"DEBUG\"]\n"), &raw).unwrap();
        assert_eq!(env.get("DEBUG").map(String::as_str), Some("*"));
    }

    /// A configured name `vm exec --env` refuses is the session's refusal,
    /// naming the key and the name, never a value, whatever the environment holds.
    #[test]
    fn a_refused_name_is_never_forwarded_and_named_in_the_refusal() {
        let secret = format!("{}{}", "AKIA", "Q".repeat(16));
        for (toml, name) in [
            ("[wrapper]\nenv_extra = [\"GITHUB_TOKEN\"]\n", "GITHUB_TOKEN"),
            ("[wrapper]\nenv_extra = [\"aws_profile\"]\n", "aws_profile"),
            ("[wrapper]\nenv_forward = [\"LANG\", \"NODE_OPTIONS\"]\n", "NODE_OPTIONS"),
            ("[wrapper]\nenv_extra = [\"HOME\"]\n", "HOME"),
            ("[wrapper]\nenv_extra = [\"https_proxy\"]\n", "https_proxy"),
            ("[wrapper]\nenv_extra = [\"OPENAI_API_KEY\"]\n", "OPENAI_API_KEY"),
            ("[wrapper]\nenv_forward = [\"LANG\", \"CLAUDE_CODE_PROJECT_DIR_NAME\"]\n", "CLAUDE_CODE_PROJECT_DIR_NAME"),
        ] {
            let ext = |_: &str| Some(OsString::from(secret.clone()));
            let e = session_env(&cfg(toml), &ext).unwrap_err();
            assert!(e.contains(&format!(" names {name}: ")) && !e.contains(&secret), "{toml}: {e}");
        }
        let e = session_env(&cfg("[wrapper]\nenv_extra = [\"BAD-NAME\"]\n"), &|_| None).unwrap_err();
        assert!(e.starts_with("[wrapper].env_extra holds \"BAD-NAME\": not a variable name"), "{e}");
    }

    /// S12 (R2-3): a refresh name ([`HOST_REFRESH_NAMES`], the two in that
    /// order) in `env_forward` (beside `LANG`) or in `env_extra`, as given or
    /// lowercased, is the session's refusal: exactly the frozen text with that
    /// key and that spelling, no value of Cursor's, within `PART_MAX` (so the
    /// fix survives the line's cut), and a text the line's scrub leaves as it
    /// is (its reason in parentheses after the name: a `:` there would mask the
    /// rest, §R0 item 12). `vm exec --env` does not learn them (R2-5).
    #[test]
    fn a_host_refresh_name_is_refused_in_env_forward_and_env_extra() {
        assert_eq!(HOST_REFRESH_NAMES, ["CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH", "CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH"]);
        let value = format!("{}-{}", "refresh", "Zq9".repeat(8));
        let ext = |_: &str| Some(OsString::from(value.clone()));
        for name in HOST_REFRESH_NAMES {
            assert_eq!(refused_name(name), None, "{name}: vm exec --env is unchanged");
            for spelled in [name.to_string(), name.to_ascii_lowercase()] {
                for (key, toml) in [("env_forward", format!("[wrapper]\nenv_forward = [\"LANG\", \"{spelled}\"]\n")), ("env_extra", format!("[wrapper]\nenv_extra = [\"{spelled}\"]\n"))] {
                    let e = session_env(&cfg(&toml), &ext).unwrap_err();
                    assert_eq!(e, format!("[wrapper].{key} names {spelled} (the wrapper answers a remote CLI's refreshes with no token); remove it from bridge.toml"));
                    assert!(!e.contains(&value), "no value of Cursor's: {e}");
                    assert!(e.chars().count() <= crate::bridge::remote::PART_MAX, "{} characters: {e}", e.chars().count());
                    assert_eq!(crate::wire::redact::scrub(&e), e, "the scrub keeps it whole");
                }
            }
        }
    }

    /// P4 on a vpc VM (`agent::exec::spawn_env`): the six proxy variables
    /// first, then the session's names, none of which can be a proxy name
    /// (refused above), so the session never replaces the VM's proxy.
    #[test]
    fn on_a_vpc_vm_the_proxy_variables_come_first_and_stay() {
        use crate::bridge::vm::registry::VmRow;
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::bridge::vm::cmd::Ctx { paths: crate::bridge::config::Paths::from_root_and_env(dir.path().to_path_buf(), None), cfg: BridgeConfig::default(), knobs: crate::bridge::lab::VmKnobs::default() };
        let session = session_env(&ctx.cfg, &env_of(&[("LANG", "C.UTF-8")])).unwrap();
        let pairs: Vec<(String, String)> = session.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let vpc = VmRow { egress: "vpc".into(), ..VmRow::default() };
        let env = crate::bridge::agent::exec::spawn_env(&ctx, &vpc, &pairs);
        let proxy = crate::bridge::egress::proxy_url(crate::bridge::egress::PROXY_IP, crate::bridge::egress::PROXY_PORT);
        for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
            assert_eq!(env.get(name), Some(&proxy), "{name}");
        }
        assert_eq!((env.get("no_proxy").map(String::as_str), env.get("NO_PROXY").map(String::as_str)), (Some(crate::bridge::egress::NO_PROXY), Some(crate::bridge::egress::NO_PROXY)));
        assert_eq!(env.len(), session.len() + PROXY_VARS, "{env:?}");
        assert!(session.iter().all(|(k, v)| env.get(k) == Some(v)), "the session's names after them");
    }

    /// A spawn takes `ENV_MAX_ENTRIES` names with the six proxy ones.
    #[test]
    fn too_many_names_are_refused() {
        let names: Vec<String> = (0..ENV_MAX_ENTRIES).map(|i| format!("\"V{i}\"")).collect();
        let toml = format!("[wrapper]\nenv_extra = [{}]\n", names.join(", "));
        let e = session_env(&cfg(&toml), &|_| Some(OsString::from("x"))).unwrap_err();
        assert!(e.contains(&format!("at most {}", ENV_MAX_ENTRIES - PROXY_VARS)), "{e}");
    }
}
