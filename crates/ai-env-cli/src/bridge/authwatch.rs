//! Was the delivered credential rejected? (S7 D6.) A pure watch over a
//! `claude` command's output, used by `vm exec --with-credential` and `vm
//! smoke --with-credential` now and by S8's pump later. It only reads: the
//! output bytes always pass through unchanged, and nothing here decides what
//! reaches the operator.
//!
//! Three kinds of evidence, all from the lines the command prints:
//! - **A retry 401.** A stream-json `system` line of subtype `api_retry`
//!   whose `error` is `authentication_failed` or whose status is 401. Claude
//!   retries those itself; at the [`RETRY_LIMIT`]th since the command's last
//!   progress the watch says [`Verdict::Rejected`] and `vm exec` stops the
//!   command (TERM to its group) instead of letting it retry on.
//! - **A result 401.** A `result` line with `is_error` true and
//!   `api_error_status` 401, whatever its `result` says: the status the CLI
//!   reports, not its wording, tells it.
//! - **A text 401.** A line starting with one of [`TEXT_SIGNATURES`], or a
//!   `{"type":"result","is_error":true}` line whose `result` starts with one:
//!   for output that carries no status (plain text, or a CLI that reports none).
//!
//! A result 401 or a text 401 counts only when the command then exits 1
//! ([`AuthWatch::rejected_at_exit`]): a 401 the command recovered from is no
//! rejection. `vm exec` audits either as `text`.
//!
//! **A remote session** (S8, [`AuthWatch::for_session`]): the CLI in the VM
//! runs as long as its stdin stays open, and [`AUTH_TIMERS`] measured that it
//! never exits after a failed turn while it does (`exits_while_stdin_open`
//! false), so the exit 1 that confirms a result or a text 401 never comes.
//! When the VM's claude is the version those timers were measured on, a
//! result 401 or a text 401 is a [`Verdict::Rejected`] at once; for any other
//! version only the retry rule stops the session (and the exit rule still
//! reads its exit, should it come).
//!
//! **Progress clears all three**: an `assistant` line that is not an API error
//! (no `error`, not the CLI's `<synthetic>` message) is a model reply, and a
//! `result` that is not `is_error` is an answered turn; either shows the token
//! works. The retries counted are therefore those with no progress between
//! them, not every one of a long command (a multi-turn stream-json session,
//! S8's pump): a refused token fails every request, so its retries add up
//! across requests, while a valid token that met a transient 401 answers in
//! between. Counting per request (by `attempt`) would not do: the CLI may
//! give a refused token fewer than [`RETRY_LIMIT`] attempts per request. An
//! error result, a non-auth retry and anything else clear nothing.
//!
//! A reply can be long: claude prints each content block as an `assistant`
//! line of its own, so a Write of a large file is one line over [`LINE_MAX`].
//! Such a line is never parsed whole: its first [`HEAD_MAX`] bytes decide,
//! read as stream-json prints a reply (`type` first, then the API's message,
//! whose `model` comes before its content: claude 2.1.288's order, and
//! 2.1.296's as B16 printed it, `model` the message's first key at byte 31
//! and `content` at byte 131). It is progress when it starts
//! `{"type":"assistant"` and names a model other than `<synthetic>` before
//! the cut, with no `"error"` there, or starts `{"type":"result"` with
//! `"is_error":false` before the cut. Any other long line (an echoed user
//! message, the init line) clears nothing; the CLI's own error lines are
//! short, and read whole. claude 2.1.296 prints a `result` starting
//! `{"duration_api_ms":`, its `type` after its `result` (B7's error result
//! and B16's answered one, whose `is_error` comes at byte 1503 of 1804, past
//! the cut), so that second start matches none of its results: an answered
//! one over [`LINE_MAX`] clears nothing, while the reply before it still
//! does, which is accepted. A line read whole is judged whatever its key
//! order.
//!
//! A line that is a JSON array is read as a run's messages: each object in
//! it is judged as a line of its own would be, in order, and anything else
//! in it is nothing. claude's `--output-format json --verbose` prints its
//! messages so, as one line at the run's end: pinned from B16 on 2.1.296
//! (below), one array of the messages a stream-json run prints one per
//! line. The limit is judged at the line's end, as for any line: the run is
//! over by then, so a reply after a third retry in the same array is a
//! recovery, not a stop due before it. An array over [`LINE_MAX`] is passed
//! over as any long line is, and its head shows no progress.
//!
//! Never evidence: 429, 5xx, a connection error, the egress proxy's own 403
//! or any other 4xx but 401 (as text, or as a result's `api_error_status`),
//! or a line over [`LINE_MAX`] bytes (its head shows progress, no more). A
//! 429 includes the account's usage limit (S10 addendum A1: claude 2.1.305's
//! `usage_limit_reached` result, `You've hit your weekly limit · …`), which is
//! no progress either: the pump's usage tap reads it (`wire::ratelimit`).
//!
//! **Pinned from B7** (S7 part B, 11 Oct 2026), no longer provisional: claude
//! 2.1.296 given a garbage setup-token on fd 3 on a vpc MicroVM. With
//! `-p … --output-format stream-json --verbose` it printed its init line, two
//! `api_retry` lines (`attempt` 1 and 2 of `max_retries` 10, `error_status`
//! 401, `error` `authentication_failed`), a `<synthetic>` assistant line
//! carrying the refusal's text (no progress), then an error `result` with
//! `api_error_status` 401 and the text
//! `Failed to authenticate. API Error: 401 OAuth access token is invalid.`,
//! and exited 1; with `--output-format json` it printed the same `result`
//! alone, and exited 1. A `-p` run so ends on its result before the third
//! retry: the result 401 refuses it, and the text 401 would on its own.
//! Those lines, trimmed, are `tests/fixtures/claude/refused-*-2.1.296.*`,
//! which this module's tests read, and are kept nowhere else: B7's rerun
//! (the GO) wrote over `target/s7/b7-stream.jsonl` and `b7-result.json`,
//! which hold the rerun's lines whole, the same shape (`retry_delay_ms` 524
//! and 1247 where the first run's were 507 and 1246). B14 repeats the run as
//! `live_credential_garbage_token_is_refused_with_exit_5`, which prints the
//! same lines. [`AUTH_TIMERS`] is not B7's: it is the `oauth-t1` row's (B11).
//!
//! **Pinned from B16** (the same day): claude 2.1.296, Cursor's bundled one
//! on the Mac, given the valid sealed setup-token by `ai-env run` with a
//! throwaway config dir. With `-p … --output-format stream-json --verbose`
//! it printed its init line, the reply (an `assistant` line, its message's
//! keys in the order above, no `error`), a `rate_limit_event` line and the
//! answered `result` (`is_error` false, starting `{"duration_api_ms":`);
//! with `--output-format json --verbose` it printed its run's four messages,
//! the same kinds in the same order, as one array on one line. The
//! `rate_limit_event` line is nothing, as any line of another type: neither
//! progress nor evidence. Those lines, trimmed, are
//! `tests/fixtures/claude/valid-*-2.1.296.*`, which this module's tests read
//! (`target/s7/valid-stream.jsonl` and `valid-json-verbose.json` keep them
//! whole).

/// Retry 401s with no progress between them before the command is stopped.
/// Pinned from B7 (claude 2.1.296): a `-p` run gives up after two auth
/// retries (its `api_retry` lines say `max_retries` 10, yet it printed two),
/// so the limit is never reached there and the result rule ends it at the
/// exit (a result 401, then exit 1: `vm exec` exits 5 saying the command
/// exited). The limit stops what retries on: a long session whose requests
/// all fail (S8's pump).
pub const RETRY_LIMIT: u32 = 3;
/// The CLI's own auth timers, as the `oauth-t1` row measured them (S7 B11,
/// 11 Oct 2026, claude 2.1.296; again S8 part B, 17 Oct 2026, claude
/// 2.1.302: `plans/s8-measurements.md`; again S10 part B, 21 Oct 2026,
/// claude 2.1.305: `plans/s10-measurements.md`), keyed to the claude version
/// they name (`claude`, 2.1.305): a new one is measured again with
/// `ai-env lab run oauth-t1` before they are trusted for it. S8's wrapper
/// and S12's refresh relay read them: S8 is to compare `claude` with the
/// version of the CLI it runs, a different version being unmeasured until
/// `oauth-t1` runs again. No test ties `claude` to `image/claude.lock`:
/// `make claude-pin` moves that pin (S11), and chats may run a newer one.
/// Measured, run as `claude-vscode` with `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1`
/// and a token Anthropic refuses: the CLI asked for a refresh at the first
/// 401, 0.96-1.44 s after the spawn (its start-up and that request: no wait
/// of its own); with no answer the turn failed 30.0 s after the ask, and the
/// CLI did not exit while its stdin stayed open (killed at the probe's 150 s
/// bound); a null answer failed the turn 1.1 s after the ask, and 1.1 s
/// after its stdin closed the CLI exited 1; `CLAUDE_CODE_OAUTH_401_WAIT_MS=5000`
/// moved the ask 5.0 s later, and the null answer's failed turn to 5.0 s
/// after the ask; a valid answer brought the reply 2.3 s after the ask, and
/// exit 0. These agree with what S7 read from 2.1.288's bytes (the 401 wait
/// 0 outside a remote session; the host's answer awaited 30 s). The 60 s
/// wait in a remote session and `CLAUDE_CODE_AUTH_FAIL_EXIT_MS` (600 s by
/// those bytes, past the probe's bound) stay unmeasured: ai-env's CLI is
/// never a remote child. Claude 2.1.302 (Cursor's bundle, the same runs)
/// gave the same timers: the ask 0.95-1.16 s after the spawn; with no answer
/// the turn failed 30.0 s after the ask and no exit came before the 150 s
/// bound; a null answer failed it 1.1 s after the ask, and 1.0 s after its
/// stdin closed the CLI exited 1; the 401 wait of 5000 moved the ask to
/// 5.96 s and the null answer's failed turn to 5.0 s after it; a valid
/// answer brought the reply 2.3 s after the ask, and exit 0. Claude 2.1.305
/// (Cursor's bundle, the same runs) gave the same timers: the ask 1.32-2.35 s
/// after the spawn; with no answer the turn failed 30.1 s after the ask and
/// no exit came before the 150 s bound; a null answer failed it 1.7 s after
/// the ask, and 0.9 s after its stdin closed the CLI exited 1; the 401 wait
/// of 5000 moved the ask to 6.35 s and the null answer's failed turn to
/// 5.0 s after it. Its valid answer, unlike 2.1.302's, failed the turn too,
/// 1.2 s after the ask, then exit 1: the code that asks, takes the answer
/// and retries after a 401 is 2.1.302's (the two bundles compared), and no
/// field here rests on that run. Claude 2.1.310 (Cursor's bundle, the same
/// runs: S11 part B, B1 (g), 24 Oct 2026, `logs/log56.txt`) gave the same
/// timers, so [`AUTH_TIMERS_REVIEWED`] holds its row after this one, which
/// stays 2.1.305's (the image's claude, the version the fakes print): the
/// ask 1.04-1.34 s after the spawn; with no answer the turn failed 30.0 s
/// after the ask (refresh@1339, is_error@31359) and no exit came before the
/// 150 s bound; a null answer failed it 1.0 s after the ask, and 0.9 s after
/// its stdin closed the CLI exited 1 (refresh@1312, result@2350, exit
/// 1@3298); the 401 wait of 5000 moved the ask to 6.0 s and the null
/// answer's failed turn to 5.1 s after it (refresh@6021, result@11072); a
/// valid answer brought the reply 2.1 s after the ask, and exit 0
/// (refresh@1043, result@3192, exit@3881).
pub const AUTH_TIMERS: AuthTimers = AuthTimers { claude: "2.1.305", oauth_401_wait_ms: 0, refresh_answer_timeout_ms: 30_000, exits_while_stdin_open: false };
/// S11 (L3): every claude version a reviewed `oauth-t1` run measured, oldest first, each once. `AUTH_TIMERS`
/// (2.1.305, the image's claude, which the fakes print and the tests compare with) is one of them, no longer the
/// last: 2.1.310 followed (Mike's review, 24 Oct 2026). An unmeasured version runs on the retry rule; nothing is
/// measured or inherited automatically.
pub const AUTH_TIMERS_REVIEWED: [AuthTimers; 3] = [
    AuthTimers { claude: "2.1.302", oauth_401_wait_ms: 0, refresh_answer_timeout_ms: 30_000, exits_while_stdin_open: false },
    AUTH_TIMERS,
    AuthTimers { claude: "2.1.310", oauth_401_wait_ms: 0, refresh_answer_timeout_ms: 30_000, exits_while_stdin_open: false },
];

/// The reviewed timers of `claude` (a version), when a reviewed run measured it.
#[must_use]
pub fn timers_for(claude: &str) -> Option<&'static AuthTimers> {
    AUTH_TIMERS_REVIEWED.iter().find(|t| t.claude == claude)
}
/// How long a turn whose model requests all fail without a refusal (an
/// egress that blocks api.anthropic.com, an outage) may take before the CLI
/// gives up by itself, measured on [`AUTH_FAIL_BUDGET_CLAUDE`]: S7 B10
/// (11 Oct 2026, claude 2.1.296) measured 179 s of the CLI's own retries
/// against the proxy's 403s, then a result with `is_error` and exit 1 (never
/// 5: nothing was refused). S8's tests and part B judge a blocked turn
/// against it (plan L8); the wrapper does not enforce it.
pub const AUTH_FAIL_BUDGET_MS: u64 = 200_000;
/// The claude [`AUTH_FAIL_BUDGET_MS`] was measured on (S7 B10). Unlike
/// [`AUTH_TIMERS`], it was not measured again for 2.1.302 or 2.1.305 (S8's
/// and S10's part B ran no blocked turn on them).
pub const AUTH_FAIL_BUDGET_CLAUDE: &str = "2.1.296";
/// Longest line inspected; a longer one is passed over, its head aside.
pub const LINE_MAX: usize = 64 * 1024;
/// What is kept of a line passed over: its first bytes, which tell a model
/// reply or an answered turn (progress) by how they start (the module doc).
pub const HEAD_MAX: usize = 512;
/// How a refused credential reads in claude's own text. Matched at the start
/// of a line, or of an `is_error` result's `result`, after leading
/// whitespace. Pinned from B7 on claude 2.1.296 (the module doc), no longer
/// provisional: its refusal's text starts
/// `Failed to authenticate. API Error: 401`, which no part-A signature
/// matches at the start, hence the first. The three part-A signatures are
/// kept, unmeasured (no S7 run printed a line or a result starting with
/// one), for plain text the CLI may print without B7's prefix (its 401
/// message alone, an API key's refusal, an expired token's): like the
/// first, each is matched only at a start and counts only with exit 1.
pub const TEXT_SIGNATURES: [&str; 4] = ["Failed to authenticate. API Error: 401", "API Error: 401", "Invalid API key", "OAuth token has expired"];

/// The CLI's auth timers for one claude version ([`AUTH_TIMERS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthTimers {
    /// The version measured: `claude --version`'s first word for the CLI
    /// `oauth-t1` ran (Cursor's bundled one on the Mac; `image/claude.lock`
    /// pinned the same on 11 Oct 2026, but nothing keeps the two equal).
    pub claude: &'static str,
    /// The wait after a 401 before the CLI asks its host for a refresh, with
    /// `CLAUDE_CODE_OAUTH_401_WAIT_MS` unset, outside a remote session
    /// (ai-env sets it only in `oauth-t1`'s knob run).
    pub oauth_401_wait_ms: u64,
    /// How long the CLI awaits its host's answer to `oauth_token_refresh`
    /// before it fails the turn with an `is_error` result.
    pub refresh_answer_timeout_ms: u64,
    /// Whether a CLI that is not a remote child (no
    /// `CLAUDE_CODE_REMOTE_SESSION_ID`, which ai-env never sets) exits of its
    /// own accord after a failed turn while its stdin stays open.
    pub exits_while_stdin_open: bool,
}

/// Which stream a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// What a chunk added up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to act on (yet).
    Watching,
    /// The [`RETRY_LIMIT`]th retry 401 with no progress between them (or,
    /// for [`AuthWatch::for_session`] on the measured claude, a result or a
    /// text 401): stop the command now. Said once, by the chunk that
    /// completes that line.
    Rejected,
}

/// One partial line per stream, bounded by [`LINE_MAX`].
#[derive(Debug, Default)]
struct Partial {
    buf: Vec<u8>,
    /// The line in progress is past `LINE_MAX`: it is skipped to its end,
    /// and `buf` keeps only its head ([`HEAD_MAX`] bytes).
    skipping: bool,
}

/// The watch over one command's stdout and stderr.
#[derive(Debug, Default)]
pub struct AuthWatch {
    out: Partial,
    err: Partial,
    /// Retry 401s since the last progress (see the module doc).
    retries: u32,
    /// A text 401 or a result 401 since the last progress (one flag: both
    /// count only with exit 1, and are audited alike).
    text_401: bool,
    /// A remote session's watch on the measured claude ([`AuthWatch::for_session`]):
    /// a text 401 or a result 401 is a verdict at once.
    at_once: bool,
    said: bool,
    /// How the verdict was reached, once said: `retries` or `text`.
    said_how: Option<&'static str>,
}

impl AuthWatch {
    #[must_use]
    pub fn new() -> AuthWatch {
        AuthWatch::default()
    }

    /// The watch over a remote session's CLI (S8, the module doc):
    /// `timers_match` when the VM's claude is [`AUTH_TIMERS`]' version, so a
    /// result 401 or a text 401 is said at once ([`Verdict::Rejected`]);
    /// otherwise the retry rule alone says it.
    #[must_use]
    pub fn for_session(timers_match: bool) -> AuthWatch {
        AuthWatch { at_once: timers_match, ..AuthWatch::default() }
    }

    /// How the [`Verdict::Rejected`] [`AuthWatch::feed`] said was reached:
    /// `retries` ([`RETRY_LIMIT`] retry 401s) or `text` (a result or a text
    /// 401, [`AuthWatch::for_session`]'s at-once rule); `None` before it.
    #[must_use]
    pub fn verdict_how(&self) -> Option<&'static str> {
        self.said_how
    }

    /// Read `bytes` from `stream` (any chunking: a line split across chunks
    /// is put back together).
    pub fn feed(&mut self, stream: Stream, bytes: &[u8]) -> Verdict {
        let mut lines = Vec::new();
        let part = match stream {
            Stream::Stdout => &mut self.out,
            Stream::Stderr => &mut self.err,
        };
        for &b in bytes {
            if b == b'\n' {
                // A line passed over goes with its head, `true` marking it.
                lines.push((part.skipping, std::mem::take(&mut part.buf)));
                part.skipping = false;
            } else if !part.skipping {
                if part.buf.len() >= LINE_MAX {
                    part.buf.truncate(HEAD_MAX);
                    part.skipping = true;
                } else {
                    part.buf.push(b);
                }
            }
        }
        // Judged line by line: progress later in the same chunk must not
        // hide the limit a line before it reached (any chunking, one verdict).
        let mut rejected = false;
        for (long, line) in lines {
            self.judge(long, &line);
            let how = if self.retries >= RETRY_LIMIT {
                Some("retries")
            } else if self.at_once && self.text_401 {
                Some("text")
            } else {
                None
            };
            if let Some(how) = how.filter(|_| !self.said) {
                self.said = true;
                self.said_how = Some(how);
                rejected = true;
            }
        }
        if rejected {
            Verdict::Rejected
        } else {
            Verdict::Watching
        }
    }

    /// The command exited with `code`: was it refused? A text 401 or a
    /// result 401 with exit 1, or [`RETRY_LIMIT`] retry 401s with no progress
    /// after them and an exit other than 0 (a command that exits 0
    /// recovered). A last line without a newline counts too (a long one by
    /// its head).
    #[must_use]
    pub fn rejected_at_exit(&mut self, code: Option<i32>) -> bool {
        for stream in [Stream::Stdout, Stream::Stderr] {
            let part = match stream {
                Stream::Stdout => &mut self.out,
                Stream::Stderr => &mut self.err,
            };
            if !part.buf.is_empty() {
                let (long, line) = (std::mem::take(&mut part.skipping), std::mem::take(&mut part.buf));
                self.judge(long, &line);
            }
        }
        (self.retries >= RETRY_LIMIT && code != Some(0)) || (self.text_401 && code == Some(1))
    }

    /// How many retry 401s were seen since the last progress.
    #[must_use]
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// One whole line, or the head of one passed over (`long`).
    fn judge(&mut self, long: bool, line: &[u8]) {
        if long {
            self.long_line(line);
        } else {
            self.line(line);
        }
    }

    /// One whole line: a text 401 by how it starts, else one JSON message or
    /// an array of them (the module doc); anything else is nothing.
    fn line(&mut self, line: &[u8]) {
        let Ok(text) = std::str::from_utf8(line) else { return };
        let text = text.trim_start();
        if starts_with_signature(text) {
            self.text_401 = true;
            return;
        }
        if !text.starts_with(['{', '[']) {
            return;
        }
        match serde_json::from_str::<serde_json::Value>(text) {
            // `--output-format json --verbose` (pinned from B16, the module doc): a run's messages, in order.
            Ok(serde_json::Value::Array(messages)) => messages.iter().for_each(|m| self.message(m)),
            Ok(m) => self.message(&m),
            Err(_) => {}
        }
    }

    /// One message, a line of its own or an object in an array line (any
    /// key order); anything but an object is nothing.
    fn message(&mut self, v: &serde_json::Value) {
        let field = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
        match field("type") {
            Some("system") if field("subtype") == Some("api_retry") => {
                // B7's (2.1.296) carry both `error_status` 401 and `error` `authentication_failed`: either counts.
                let status = ["error_status", "status"].iter().find_map(|k| v.get(*k).and_then(serde_json::Value::as_u64));
                if field("error") == Some("authentication_failed") || status == Some(401) {
                    self.retries += 1;
                }
            }
            Some("result") => match v.get("is_error").and_then(serde_json::Value::as_bool) {
                // A result 401 (the status, whatever the words), else a text 401 in its `result`.
                Some(true) if v.get("api_error_status").and_then(serde_json::Value::as_u64) == Some(401) || field("result").is_some_and(|r| starts_with_signature(r.trim_start())) => self.text_401 = true,
                Some(false) => self.progress(),
                _ => {}
            },
            // A model reply; the CLI's own API-error message carries `error`, or is `<synthetic>`.
            Some("assistant") if v.get("error").is_none_or(serde_json::Value::is_null) && v.pointer("/message/model").and_then(serde_json::Value::as_str) != Some("<synthetic>") => self.progress(),
            _ => {}
        }
    }

    /// A line over [`LINE_MAX`], by its head alone (the module doc): never
    /// evidence, so only progress is read from it, and only when its start
    /// says so. A model's name cut off by the head, or none in it, is none:
    /// such a line clears nothing, as before any head was kept.
    fn long_line(&mut self, head: &[u8]) {
        let head = String::from_utf8_lossy(head);
        let head = head.trim_start();
        let model = head.split_once("\"model\":\"").and_then(|(_, rest)| rest.split_once('"')).map(|(model, _)| model);
        let reply = head.starts_with("{\"type\":\"assistant\"") && model.is_some_and(|m| m != "<synthetic>") && !head.contains("\"error\"");
        let answered = head.starts_with("{\"type\":\"result\"") && head.contains("\"is_error\":false");
        if reply || answered {
            self.progress();
        }
    }

    /// The command made progress (see the module doc): the token works, so
    /// what was counted against it is forgotten.
    fn progress(&mut self) {
        self.retries = 0;
        self.text_401 = false;
    }
}

fn starts_with_signature(text: &str) -> bool {
    TEXT_SIGNATURES.iter().any(|s| text.starts_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry(status: u16, error: &str) -> String {
        format!("{{\"type\":\"system\",\"subtype\":\"api_retry\",\"attempt\":1,\"error_status\":{status},\"error\":\"{error}\"}}\n")
    }

    /// A model reply and an answered turn, as stream-json prints them: progress.
    const ASSISTANT: &str = "{\"type\":\"assistant\",\"message\":{\"model\":\"claude-x\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}}\n";
    const ANSWERED: &str = "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"done\"}\n";
    /// The CLI's own messages for a failed request: never progress.
    const API_ERROR: &str = "{\"type\":\"assistant\",\"error\":\"authentication_failed\",\"message\":{\"model\":\"<synthetic>\",\"content\":[{\"type\":\"text\",\"text\":\"API Error: 401\"}]}}\n";
    const SYNTHETIC: &str = "{\"type\":\"assistant\",\"message\":{\"model\":\"<synthetic>\",\"content\":[{\"type\":\"text\",\"text\":\"API Error: 401\"}]}}\n";
    const REFUSED: &str = "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"result\":\"API Error: 401 nope\"}\n";
    /// An echoed user message: never progress, however long.
    const USER: &str = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";

    /// `line` made longer than LINE_MAX inside the string that starts after
    /// `at` (its first match): its start, the head the watch keeps, is as before.
    fn padded(line: &str, at: &str) -> String {
        line.replacen(at, &format!("{at}{}", "x".repeat(LINE_MAX)), 1)
    }

    #[test]
    fn the_third_retry_401_stops_the_command_once() {
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, retry(401, "authentication_failed").as_bytes()), Verdict::Watching);
        assert_eq!(w.feed(Stream::Stdout, retry(401, "unknown").as_bytes()), Verdict::Watching, "a 401 status counts whatever the error says");
        assert_eq!(w.feed(Stream::Stdout, retry(500, "authentication_failed").as_bytes()), Verdict::Rejected, "so does authentication_failed");
        assert_eq!(w.feed(Stream::Stdout, retry(401, "authentication_failed").as_bytes()), Verdict::Watching, "said once");
        assert!(w.rejected_at_exit(Some(143)));
    }

    /// None of these is evidence, each read on a watch of its own: on one
    /// shared watch the answered turn among them is progress and would clear
    /// whatever a line before it wrongly counted.
    #[test]
    fn what_never_counts() {
        for line in [
            retry(429, "rate_limit"),
            retry(500, "server_error"),
            retry(529, "overloaded"),
            "API Error: 403 Forbidden (the proxy)\n".to_string(),
            "API Error: 429 rate limited\n".to_string(),
            "Connection error.\n".to_string(),
            "{\"type\":\"result\",\"is_error\":true,\"result\":\"API Error: 500\"}\n".to_string(),
            "{\"type\":\"result\",\"is_error\":false,\"result\":\"API Error: 401 in a quoted answer\"}\n".to_string(),
            "the model said: API Error: 401 is a status code\n".to_string(),
            "{not json\n".to_string(),
        ] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{line}");
            assert_eq!(w.retries(), 0, "{line}");
            assert!(!w.rejected_at_exit(Some(1)), "nothing counted, whatever the exit: {line}");
        }
    }

    /// An error result is a text 401 only when its `result` starts with a
    /// signature: one that merely mentions a signature further on (here a
    /// failure quoting what a fetch said) refuses nothing, even with exit 1.
    #[test]
    fn an_error_result_that_only_mentions_a_signature_is_no_refusal() {
        let line = "{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"the fetch said: API Error: 401\"}\n";
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching);
        assert!(!w.rejected_at_exit(Some(1)));
    }

    /// A text 401 counts only with exit 1, on either stream, also as a
    /// result line or a last line without a newline.
    #[test]
    fn a_text_401_counts_only_with_exit_1() {
        for (stream, text) in [
            (Stream::Stdout, "API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"}}\n"),
            (Stream::Stderr, "  Invalid API key · Please run /login\n"),
            (Stream::Stdout, "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"result\":\"OAuth token has expired\"}\n"),
            (Stream::Stderr, "API Error: 401 at the very end"),
        ] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(stream, text.as_bytes()), Verdict::Watching);
            assert!(w.rejected_at_exit(Some(1)), "{text}");
            // The same output, then exit 0 (a last line without a newline included).
            let mut at_0 = AuthWatch::new();
            at_0.feed(stream, text.as_bytes());
            assert!(!at_0.rejected_at_exit(Some(0)), "exit 0 is a recovery: {text}");
        }
    }

    /// A text 401 is a refusal only with exit 1, the status claude gives it:
    /// the same line followed by another failing exit (2, 143 after a stop,
    /// a signal with no code) is something else, and refuses nothing.
    #[test]
    fn a_text_401_with_another_failing_exit_is_no_refusal() {
        for code in [Some(2), Some(143), None] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stderr, b"API Error: 401 nope\n"), Verdict::Watching);
            assert!(!w.rejected_at_exit(code), "exit {code:?}");
        }
    }

    /// M14: transient retry 401s that a request recovered from never add up
    /// over a long command: a model reply or an answered turn between them
    /// clears the count, and so the text 401 before it; a command that ends
    /// with exit 0 was not refused, whatever it counted.
    #[test]
    fn recovered_401s_never_add_up() {
        let mut w = AuthWatch::new();
        for turn in 1..=4 {
            assert_eq!(w.feed(Stream::Stdout, retry(401, "authentication_failed").as_bytes()), Verdict::Watching, "turn {turn}");
            let progress = if turn % 2 == 1 { ASSISTANT } else { ANSWERED };
            assert_eq!(w.feed(Stream::Stdout, progress.as_bytes()), Verdict::Watching, "turn {turn}");
            assert_eq!(w.retries(), 0, "turn {turn}: the reply cleared the count");
        }
        assert!(!w.rejected_at_exit(Some(1)), "nothing left counted against the token");
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, REFUSED.as_bytes());
        w.feed(Stream::Stdout, ANSWERED.as_bytes());
        assert!(!w.rejected_at_exit(Some(1)), "a turn answered after the text 401: an exit 1 later is something else");
        let mut w = AuthWatch::new();
        for _ in 0..3 {
            w.feed(Stream::Stdout, retry(401, "authentication_failed").as_bytes());
        }
        assert!(!w.rejected_at_exit(Some(0)), "exit 0: the command recovered, whatever it counted");
    }

    /// M14's other side: a refused token fails every request, so its
    /// retries add up across them. The CLI's own API-error message (`error`,
    /// or the `<synthetic>` model) and an error result are not progress, and
    /// neither is a non-auth retry.
    #[test]
    fn a_refused_tokens_retries_add_up_across_its_requests() {
        let mut w = AuthWatch::new();
        let (r401, r529) = (retry(401, "authentication_failed"), retry(529, "overloaded"));
        for line in [r401.as_str(), r401.as_str(), API_ERROR, REFUSED, r529.as_str(), SYNTHETIC] {
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{line}");
        }
        assert_eq!(w.retries(), 2, "nothing between them was progress");
        assert_eq!(w.feed(Stream::Stdout, r401.as_bytes()), Verdict::Rejected, "the next request's first 401 is the third");
        assert!(w.rejected_at_exit(Some(143)));
    }

    /// The limit is judged line by line: a chunk that holds the third retry
    /// 401 and then progress still says Rejected (the stop was due at that
    /// line), and progress after it does not undo the verdict.
    #[test]
    fn progress_after_the_third_in_one_chunk_still_stops_it() {
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, format!("{r401}{r401}{r401}{ASSISTANT}").as_bytes()), Verdict::Rejected);
        assert_eq!(w.retries(), 0, "the reply after it cleared the count");
        assert_eq!(w.feed(Stream::Stdout, format!("{r401}{r401}{r401}").as_bytes()), Verdict::Watching, "said once");
    }

    #[test]
    fn a_line_over_the_limit_is_passed_over_and_the_next_is_read() {
        let mut w = AuthWatch::new();
        let mut long = format!("API Error: 401 {}", "x".repeat(LINE_MAX));
        long.push('\n');
        w.feed(Stream::Stdout, long.as_bytes());
        assert!(!w.rejected_at_exit(Some(1)), "not inspected");
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, long.as_bytes());
        w.feed(Stream::Stdout, retry(401, "authentication_failed").as_bytes());
        assert_eq!(w.retries(), 1, "the line after it is read");
    }

    /// F5: a model reply on a line over LINE_MAX is progress, told by its
    /// head: transient retry 401s around long replies never add up to a
    /// stop, and nothing is left counted at the exit.
    #[test]
    fn a_long_model_reply_clears_the_count() {
        let long = padded(ASSISTANT, "\"text\":\"");
        assert!(long.trim_end().len() > LINE_MAX, "passed over");
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::new();
        for (i, line) in [&r401, &long, &r401, &long, &r401].into_iter().enumerate() {
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "line {i}");
        }
        assert_eq!(w.retries(), 1, "only the retry after the last reply counts");
        assert!(!w.rejected_at_exit(Some(1)));
    }

    /// F5 as claude prints it: a reply that is only a Write of an ~80 KB
    /// file (one `assistant` line, the API's message keys in their order,
    /// the model before the content) and the tool's result, twice, between
    /// three transient retry 401s, read in the shim's 64 KiB chunks: never a stop.
    #[test]
    fn a_reply_writing_a_large_file_clears_the_count_in_64_kib_chunks() {
        let body = "line of a fixture file\\n".repeat(80 * 1024 / 24);
        let write = format!(
            "{{\"type\":\"assistant\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-x\",\"content\":[{{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"Write\",\"input\":{{\"file_path\":\"/w/a.txt\",\"content\":\"{body}\"}}}}],\"stop_reason\":\"tool_use\",\"stop_sequence\":null,\"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}},\"parent_tool_use_id\":null,\"session_id\":\"s\",\"uuid\":\"u\"}}\n"
        );
        let result = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"toolu_1\",\"type\":\"tool_result\",\"content\":\"File created successfully at: /w/a.txt\"}]},\"parent_tool_use_id\":null,\"session_id\":\"s\",\"uuid\":\"v\"}\n";
        assert!(write.len() > LINE_MAX && serde_json::from_str::<serde_json::Value>(write.trim_end()).is_ok(), "one valid line over LINE_MAX");
        let r401 = retry(401, "authentication_failed");
        let out = format!("{r401}{write}{result}{r401}{write}{result}{r401}");
        let mut w = AuthWatch::new();
        let said: Vec<Verdict> = out.as_bytes().chunks(64 * 1024).map(|c| w.feed(Stream::Stdout, c)).collect();
        assert!(said.iter().all(|v| *v == Verdict::Watching), "{said:?}, retries {}", w.retries());
        assert_eq!(w.retries(), 1);
        assert!(!w.rejected_at_exit(Some(1)));
    }

    /// F5's other side: a long line is progress only as a model reply or an
    /// answered turn its head shows. The CLI's own API-error lines (also one
    /// whose head names a real model beside its `error`, before the message
    /// or after a short one), an error result, an echoed user message, the
    /// init line, a reply whose model comes after the cut and a long text 401
    /// clear nothing, and none of them is counted either.
    #[test]
    fn only_a_long_reply_or_answer_is_progress() {
        let r401 = retry(401, "authentication_failed");
        let late_model = "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"model\":\"claude-x\"}}\n";
        let init = "{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"claude-x\",\"tools\":[\"Bash\"]}\n";
        let error_first = "{\"type\":\"assistant\",\"error\":\"authentication_failed\",\"message\":{\"model\":\"claude-x\",\"content\":[{\"type\":\"text\",\"text\":\"API Error: 401\"}]}}\n";
        let error_after = "{\"type\":\"assistant\",\"message\":{\"model\":\"claude-x\",\"content\":[]},\"error\":\"authentication_failed\",\"session_id\":\"s\"}\n";
        for (line, progress) in [
            (padded(ASSISTANT, "\"text\":\""), true),
            (padded(ANSWERED, "\"result\":\""), true),
            (padded(API_ERROR, "\"text\":\""), false),
            (padded(SYNTHETIC, "\"text\":\""), false),
            (padded(error_first, "\"text\":\""), false),
            (padded(error_after, "\"session_id\":\""), false),
            (padded(REFUSED, "\"result\":\""), false),
            (padded(USER, "\"content\":\""), false),
            (padded(init, "\"tools\":[\""), false),
            (padded(late_model, "\"text\":\""), false),
            (padded("API Error: 401 nope\n", "401 "), false),
        ] {
            assert!(line.trim_end().len() > LINE_MAX, "passed over");
            let shown = &line[..60];
            let mut w = AuthWatch::new();
            w.feed(Stream::Stdout, format!("{r401}{r401}").as_bytes());
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{shown}");
            assert_eq!(w.retries(), if progress { 0 } else { 2 }, "{shown}");
            assert_eq!(w.feed(Stream::Stdout, r401.as_bytes()) == Verdict::Rejected, !progress, "{shown}");
            let mut alone = AuthWatch::new();
            alone.feed(Stream::Stdout, line.as_bytes());
            assert!(!alone.rejected_at_exit(Some(1)), "{shown}: never evidence");
        }
    }

    /// F5 at the exit: a long last line without a newline is judged by its
    /// head too: a reply clears the text 401 before it (exit 1 is then no
    /// refusal), an echoed user line leaves it counted.
    #[test]
    fn a_long_last_line_without_a_newline_is_judged_by_its_head() {
        for (last, refused) in [(padded(ASSISTANT, "\"text\":\""), false), (padded(USER, "\"content\":\""), true)] {
            let mut w = AuthWatch::new();
            w.feed(Stream::Stderr, b"API Error: 401 nope\n");
            w.feed(Stream::Stdout, last.trim_end().as_bytes());
            assert_eq!(w.rejected_at_exit(Some(1)), refused, "{}", &last[..40]);
        }
    }

    /// B7's kept output (claude 2.1.296 to a refused setup-token), trimmed:
    /// `tests/fixtures/claude/README.md` says how.
    const B7_STREAM: &str = include_str!("../../tests/fixtures/claude/refused-stream-json-2.1.296.jsonl");
    const B7_JSON: &str = include_str!("../../tests/fixtures/claude/refused-json-2.1.296.json");
    /// B16's kept output (claude 2.1.296 with the valid setup-token), trimmed
    /// the same way.
    const B16_STREAM: &str = include_str!("../../tests/fixtures/claude/valid-stream-json-2.1.296.jsonl");
    const B16_JSON: &str = include_str!("../../tests/fixtures/claude/valid-json-verbose-2.1.296.json");

    /// Line `i` of B7's stream-json run, with its `\n`: 0 init, 1 and 2 the
    /// retries, 3 the `<synthetic>` reply, 4 the result.
    fn b7_line(i: usize) -> String {
        let lines: Vec<&str> = B7_STREAM.lines().collect();
        assert_eq!(lines.len(), 5, "B7's stream: init, two retries, the reply, the result");
        format!("{}\n", lines[i])
    }

    /// Line `i` of B16's stream-json run, with its `\n`: 0 init, 1 the reply,
    /// 2 the `rate_limit_event` line, 3 the answered result.
    fn b16_line(i: usize) -> String {
        let lines: Vec<&str> = B16_STREAM.lines().collect();
        assert_eq!(lines.len(), 4, "B16's stream: init, the reply, the rate_limit_event line, the result");
        format!("{}\n", lines[i])
    }

    /// B7's refusal text, as claude printed it in its result.
    fn b7_text() -> String {
        let v: serde_json::Value = serde_json::from_str(B7_JSON).unwrap();
        v["result"].as_str().unwrap().to_string()
    }

    /// `line` with its first `from` replaced by `to` (which must be there:
    /// a variant that silently kept B7's line would prove nothing).
    fn swap(line: &str, from: &str, to: &str) -> String {
        assert!(line.contains(from), "{from} is not in {line}");
        line.replacen(from, to, 1)
    }

    /// B7's stream-json run, line by line, as claude 2.1.296 printed it to a
    /// refused token: the init line is nothing; the two `api_retry` 401s are
    /// counted, below the limit (no stop, and no refusal without what
    /// follows them); the `<synthetic>` reply carrying the refusal clears
    /// nothing; the error result makes it a refusal with exit 1, the exit
    /// claude gave, audited as text (two retries are not the limit), and
    /// none with exit 0. Any chunking says the same, and a turn answered
    /// after the result would clear it.
    #[test]
    fn b7s_stream_json_run_is_refused_with_exit_1_only() {
        assert!(b7_line(0).contains("\"subtype\":\"init\"") && b7_line(3).contains("\"model\":\"<synthetic>\"") && b7_line(4).contains("\"api_error_status\":401"), "the fixture's lines in B7's order");
        let mut w = AuthWatch::new();
        for (i, retries) in [(0, 0), (1, 1), (2, 2), (3, 2), (4, 2)] {
            let line = b7_line(i);
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "line {i}");
            assert_eq!(w.retries(), retries, "line {i}");
        }
        assert!(w.rejected_at_exit(Some(1)), "the result 401, then exit 1");
        assert!(w.retries() < RETRY_LIMIT, "audited as text: two retries are not the limit");
        let mut retries_only = AuthWatch::new();
        retries_only.feed(Stream::Stdout, format!("{}{}{}{}", b7_line(0), b7_line(1), b7_line(2), b7_line(3)).as_bytes());
        assert!(!retries_only.rejected_at_exit(Some(1)), "without its result, B7's run is no refusal: two retries are below the limit");
        let mut at_0 = AuthWatch::new();
        at_0.feed(Stream::Stdout, B7_STREAM.as_bytes());
        assert!(!at_0.rejected_at_exit(Some(0)), "exit 0 is a recovery");
        for size in [1, 7, 64, 4096] {
            let mut pieces = AuthWatch::new();
            assert!(B7_STREAM.as_bytes().chunks(size).all(|c| pieces.feed(Stream::Stdout, c) == Verdict::Watching), "chunks of {size}");
            assert!(pieces.rejected_at_exit(Some(1)) && pieces.retries() == 2, "chunks of {size}");
        }
        let mut answered = AuthWatch::new();
        answered.feed(Stream::Stdout, format!("{B7_STREAM}{ANSWERED}").as_bytes());
        assert!(!answered.rejected_at_exit(Some(1)), "a turn answered after the result 401: an exit 1 later is something else");
    }

    /// B7's json run: its one result object, then exit 1, is a refusal (as
    /// text: no retry was printed); with exit 0, another failing exit or a
    /// signal it is none.
    #[test]
    fn b7s_json_run_is_refused_with_exit_1_only() {
        for code in [Some(1), Some(0), Some(2), Some(143), None] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stdout, B7_JSON.as_bytes()), Verdict::Watching);
            assert_eq!(w.retries(), 0);
            assert_eq!(w.rejected_at_exit(code), code == Some(1), "exit {code:?}");
        }
    }

    /// The result rule reads the status, not the words: B7's result whose
    /// `result` no signature starts (reworded, or absent) is still a refusal
    /// with exit 1. The text rule needs no status: that result without its
    /// `api_error_status` is one by B7's words alone. With neither, it is
    /// nothing.
    #[test]
    fn a_result_401_is_told_by_its_status_and_a_text_401_by_its_words() {
        let (result, text) = (b7_line(4), b7_text());
        let other = "Your session could not be verified.";
        let no_status = swap(&result, ",\"api_error_status\":401", "");
        for (line, refused) in [
            (swap(&result, &text, other), true),
            (swap(&result, &format!(",\"result\":\"{text}\""), ""), true),
            (no_status.clone(), true),
            (swap(&no_status, &text, other), false),
        ] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{line}");
            assert_eq!(w.rejected_at_exit(Some(1)), refused, "{line}");
        }
    }

    /// B7's text as a plain-text run prints its refusal, on either stream,
    /// indented, or as a last line without a newline: a refusal with exit 1,
    /// none with exit 0.
    #[test]
    fn b7s_text_on_a_line_of_its_own_counts_only_with_exit_1() {
        let text = b7_text();
        for (stream, line) in [(Stream::Stdout, format!("{text}\n")), (Stream::Stderr, format!("  {text}\n")), (Stream::Stdout, text.clone())] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(stream, line.as_bytes()), Verdict::Watching, "{line}");
            assert!(w.rejected_at_exit(Some(1)), "{line}");
            let mut at_0 = AuthWatch::new();
            at_0.feed(stream, line.as_bytes());
            assert!(!at_0.rejected_at_exit(Some(0)), "exit 0 is a recovery: {line}");
        }
    }

    /// Where B7's words and status never make a refusal, each read on a
    /// watch of its own and followed by exit 1: a model's answer quoting the
    /// text (a reply line, mid-line in plain text), B7's result with
    /// `is_error` false (an answered turn, whatever its status), an error
    /// result whose `api_error_status` is not 401 (a 4xx that is no auth
    /// refusal: 400, a prompt too long; 404; 407, a proxy's; 413; 429; a 5xx:
    /// 500, 529; or the egress proxy's 403, worded as B7's was or not), the
    /// proxy's 403 as plain text, and B7's result over `LINE_MAX` (never
    /// evidence).
    #[test]
    fn b7s_words_and_status_count_nowhere_else() {
        let (result, text) = (b7_line(4), b7_text());
        let answered = swap(&result, "\"is_error\":true", "\"is_error\":false");
        let mut lines = vec![
            format!("{{\"type\":\"assistant\",\"message\":{{\"model\":\"claude-x\",\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"{text}\"}}]}}}}\n"),
            format!("the model said: {text}\n"),
            answered.clone(),
            swap(&answered, ",\"api_error_status\":401", ""),
            "Failed to authenticate. API Error: 403 Forbidden (the proxy)\n".to_string(),
            padded(&result, "\"terminal_reason\":\""),
        ];
        for (status, words) in [
            (400, "API Error: 400 invalid_request_error: prompt is too long"),
            (404, "API Error: 404 not_found_error"),
            (407, "API Error: 407 Proxy Authentication Required"),
            (413, "API Error: 413 request_too_large"),
            (429, "API Error: 429 rate_limit_error"),
            (500, "API Error: 500 api_error"),
            (529, "API Error: 529 overloaded_error"),
            (403, "API Error: 403 Forbidden"),
            (403, "Failed to authenticate. API Error: 403 Forbidden"),
        ] {
            lines.push(swap(&swap(&result, "\"api_error_status\":401", &format!("\"api_error_status\":{status}")), &text, words));
        }
        for line in lines {
            // Far enough to show a result's status and the start of its words.
            let shown = &line[..line.len().min(160)];
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{shown}");
            assert_eq!(w.retries(), 0, "{shown}");
            assert!(!w.rejected_at_exit(Some(1)), "{shown}");
        }
    }

    /// `lines` as one JSON array on one line, the shape claude's
    /// `--output-format json --verbose` prints (B16, the module doc).
    fn array(lines: &[String]) -> String {
        format!("[{}]\n", lines.iter().map(|l| l.trim_end()).collect::<Vec<_>>().join(","))
    }

    /// An array line is read message by message (the shape B16 pinned on a
    /// valid run, which `b16s_json_verbose_run_is_read_message_by_message`
    /// reads; B7 ran json without `--verbose`, so B7's five messages stand in
    /// for a refused run). In one array they count as they do on five lines:
    /// the retries 1 and 2, then the result 401, a refusal with exit 1 (as
    /// text), none with exit 0 or 2, in any chunking. Each message is judged
    /// as its own line would be: B7's result answered (`is_error` false)
    /// after the retries, or followed by an answered turn, is no refusal, and
    /// a string or a number in the array (B7's text, 401) is nothing. The
    /// limit is judged at the array's end, the run being over: three retries
    /// then a reply stop nothing, three with only the result after them stop
    /// it once. An array over `LINE_MAX` counts nothing, as any long line.
    #[test]
    fn a_json_verbose_array_is_read_message_by_message() {
        let b7: Vec<String> = (0..5).map(b7_line).collect();
        let run = array(&b7);
        assert_eq!(serde_json::from_str::<serde_json::Value>(run.trim_end()).ok().and_then(|v| v.as_array().map(Vec::len)), Some(5), "one valid array line");
        for code in [Some(1), Some(0), Some(2)] {
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stdout, run.as_bytes()), Verdict::Watching, "exit {code:?}");
            assert_eq!(w.retries(), 2, "exit {code:?}");
            assert_eq!(w.rejected_at_exit(code), code == Some(1), "exit {code:?}");
        }
        for size in [1, 64] {
            let mut pieces = AuthWatch::new();
            assert!(run.as_bytes().chunks(size).all(|c| pieces.feed(Stream::Stdout, c) == Verdict::Watching), "chunks of {size}");
            assert!(pieces.rejected_at_exit(Some(1)), "chunks of {size}");
        }
        let answered = swap(&b7[4], "\"is_error\":true", "\"is_error\":false");
        for lines in [vec![b7[1].clone(), b7[2].clone(), answered], vec![b7[4].clone(), ANSWERED.to_string()], vec![format!("\"{}\"", b7_text()), "401".to_string()]] {
            let line = array(&lines);
            let mut w = AuthWatch::new();
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{line}");
            assert_eq!(w.retries(), 0, "{line}");
            assert!(!w.rejected_at_exit(Some(1)), "{line}");
        }
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, array(&[r401.clone(), r401.clone(), r401.clone(), ASSISTANT.to_string()]).as_bytes()), Verdict::Watching, "a reply after the third: a recovery");
        assert!(!w.rejected_at_exit(Some(1)));
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, array(&[r401.clone(), r401.clone(), r401.clone(), b7[4].clone()]).as_bytes()), Verdict::Rejected);
        assert!(w.rejected_at_exit(Some(1)) && w.retries() == RETRY_LIMIT, "audited as retries");
        let long = array(&[padded(&b7[0], "\"model\":\""), b7[4].clone()]);
        assert!(long.trim_end().len() > LINE_MAX, "passed over");
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, long.as_bytes()), Verdict::Watching);
        assert!(!w.rejected_at_exit(Some(1)), "an array over LINE_MAX counts nothing");
    }

    /// B16's stream-json run, as claude 2.1.296 printed it with a valid
    /// token: nothing in it is counted, line by line or read whole in chunks
    /// of 1 or 64 bytes, and it is no refusal at exit 0 or 1.
    #[test]
    fn b16s_stream_json_run_is_no_refusal() {
        assert!(b16_line(0).contains("\"subtype\":\"init\"") && b16_line(1).starts_with("{\"type\":\"assistant\"") && b16_line(2).starts_with("{\"type\":\"rate_limit_event\"") && b16_line(3).contains("\"is_error\":false"), "the fixture's lines in B16's order");
        for code in [Some(0), Some(1)] {
            let mut w = AuthWatch::new();
            for i in 0..4 {
                assert_eq!(w.feed(Stream::Stdout, b16_line(i).as_bytes()), Verdict::Watching, "line {i}");
                assert_eq!(w.retries(), 0, "line {i}");
            }
            assert!(!w.rejected_at_exit(code), "exit {code:?}");
            for size in [1, 64] {
                let mut pieces = AuthWatch::new();
                assert!(B16_STREAM.as_bytes().chunks(size).all(|c| pieces.feed(Stream::Stdout, c) == Verdict::Watching), "chunks of {size}");
                assert!(pieces.retries() == 0 && !pieces.rejected_at_exit(code), "chunks of {size}, exit {code:?}");
            }
        }
    }

    /// B16's reply is progress: two retry 401s, the reply, then one more
    /// leave one counted (no stop, and no refusal at exit 1), while three
    /// with no line between them stop the command.
    #[test]
    fn b16s_reply_is_progress() {
        let (r401, reply) = (retry(401, "authentication_failed"), b16_line(1));
        let mut w = AuthWatch::new();
        for (line, retries) in [(&r401, 1), (&r401, 2), (&reply, 0), (&r401, 1)] {
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{line}");
            assert_eq!(w.retries(), retries, "{line}");
        }
        assert!(!w.rejected_at_exit(Some(1)));
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, format!("{r401}{r401}{r401}").as_bytes()), Verdict::Rejected);
    }

    /// B16's answered result, read whole, is progress whatever its key order
    /// (`type` after `result`, `api_error_status` null): two retry 401s and
    /// a text 401 before it leave nothing counted, and exit 1 is no refusal.
    #[test]
    fn b16s_answered_result_is_progress() {
        let (r401, answered) = (retry(401, "authentication_failed"), b16_line(3));
        assert!(answered.starts_with("{\"duration_api_ms\":") && answered.contains("\"api_error_status\":null,\"result\":\"OK\",\"type\":\"result\""), "B16's key order");
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, format!("{r401}{r401}API Error: 401 nope\n").as_bytes());
        assert_eq!(w.feed(Stream::Stdout, answered.as_bytes()), Verdict::Watching);
        assert!(w.retries() == 0 && !w.rejected_at_exit(Some(1)));
    }

    /// The head rule over B16's real key order (the module doc): its reply,
    /// lengthened past LINE_MAX by its text (its first bytes as printed, the
    /// model at byte 31), clears the count; the same line naming the
    /// `<synthetic>` model, or with an `"error"` key in its head, clears
    /// nothing, and neither does its answered result lengthened so (it
    /// starts `{"duration_api_ms":`). That is accepted: in B16's run the
    /// reply before that result still clears the retries. None is counted.
    #[test]
    fn the_head_rule_reads_b16s_key_order() {
        let r401 = retry(401, "authentication_failed");
        let reply = padded(&b16_line(1), "\"text\":\"");
        assert!(reply.starts_with("{\"type\":\"assistant\",\"message\":{\"model\":\"claude-sonnet-5-5\",") && reply.find("\"model\"") == Some(31), "B16's first bytes");
        let synthetic = swap(&reply, "\"model\":\"claude-sonnet-5-5\"", "\"model\":\"<synthetic>\"");
        let error = swap(&reply, "\"message\":{", "\"error\":\"authentication_failed\",\"message\":{");
        assert!(error[..HEAD_MAX].contains("\"model\":\"claude-sonnet-5-5\""), "the model still in the head");
        let result = padded(&b16_line(3), "\"result\":\"");
        for (line, progress) in [(&reply, true), (&synthetic, false), (&error, false), (&result, false)] {
            assert!(line.trim_end().len() > LINE_MAX, "passed over");
            let shown = &line[..80];
            let mut w = AuthWatch::new();
            w.feed(Stream::Stdout, format!("{r401}{r401}").as_bytes());
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{shown}");
            assert_eq!(w.retries(), if progress { 0 } else { 2 }, "{shown}");
            assert_eq!(w.feed(Stream::Stdout, r401.as_bytes()) == Verdict::Rejected, !progress, "{shown}");
            let mut alone = AuthWatch::new();
            alone.feed(Stream::Stdout, line.as_bytes());
            assert!(!alone.rejected_at_exit(Some(1)), "{shown}: never evidence");
        }
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, format!("{r401}{r401}{}{}{}{result}", b16_line(0), b16_line(1), b16_line(2)).as_bytes());
        assert_eq!(w.retries(), 0, "the reply before the long result cleared the count");
        assert!(!w.rejected_at_exit(Some(1)));
    }

    /// B16's `rate_limit_event` line is nothing. Not progress: two retry 401s
    /// before it stay counted and a third after it stops the command, and
    /// B7's result 401 before it is still a refusal with exit 1. Not
    /// evidence: alone, then exit 1, it is no refusal.
    #[test]
    fn b16s_rate_limit_event_is_nothing() {
        let (r401, event) = (retry(401, "authentication_failed"), b16_line(2));
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, format!("{r401}{r401}").as_bytes());
        assert_eq!(w.feed(Stream::Stdout, event.as_bytes()), Verdict::Watching);
        assert_eq!(w.retries(), 2);
        assert_eq!(w.feed(Stream::Stdout, r401.as_bytes()), Verdict::Rejected);
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, format!("{}{event}", b7_line(4)).as_bytes());
        assert!(w.rejected_at_exit(Some(1)));
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, event.as_bytes()), Verdict::Watching);
        assert!(w.retries() == 0 && !w.rejected_at_exit(Some(1)));
    }

    /// A1: claude 2.1.305's usage-limit result (S10 part B's B2, the
    /// fixture as captured) is nothing. No evidence: alone, then exit 1, it
    /// is no refusal, and a session on the measured claude does not stop.
    /// No progress: two retry 401s before it stay counted, and a third
    /// after it stops the command.
    #[test]
    fn the_usage_limit_result_is_nothing() {
        let limit = include_str!("../../tests/fixtures/claude/usage-limit-result-2.1.305.json");
        assert!(limit.contains("\"api_error_status\":429") && limit.contains("\"is_error\":true"), "the fixture is B2's 429");
        let mut w = AuthWatch::new();
        assert_eq!(w.feed(Stream::Stdout, limit.as_bytes()), Verdict::Watching);
        assert!(w.retries() == 0 && !w.rejected_at_exit(Some(1)), "no refusal at exit 1");
        let mut w = AuthWatch::for_session(true);
        assert_eq!((w.feed(Stream::Stdout, limit.as_bytes()), w.verdict_how()), (Verdict::Watching, None));
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, format!("{r401}{r401}").as_bytes());
        assert_eq!(w.feed(Stream::Stdout, limit.as_bytes()), Verdict::Watching);
        assert_eq!(w.retries(), 2, "no progress: the retries stay counted");
        assert_eq!(w.feed(Stream::Stdout, r401.as_bytes()), Verdict::Rejected);
    }

    /// B16's json `--verbose` run: one line, the array of its run's four
    /// messages (init, the reply, `rate_limit_event`, the answered result),
    /// judged message by message: after two retry 401s it clears them, and
    /// it is no refusal at exit 1, read whole or in chunks of 1 or 64 bytes.
    #[test]
    fn b16s_json_verbose_run_is_read_message_by_message() {
        let v: serde_json::Value = serde_json::from_str(B16_JSON).unwrap();
        let types: Vec<&str> = v.as_array().map(|a| a.iter().filter_map(|m| m["type"].as_str()).collect()).unwrap_or_default();
        assert!(B16_JSON.lines().count() == 1 && B16_JSON.ends_with("]\n") && types == ["system", "assistant", "rate_limit_event", "result"], "{types:?}");
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::new();
        w.feed(Stream::Stdout, format!("{r401}{r401}").as_bytes());
        assert_eq!(w.feed(Stream::Stdout, B16_JSON.as_bytes()), Verdict::Watching);
        assert_eq!(w.retries(), 0, "the array's reply clears them");
        assert!(!w.rejected_at_exit(Some(1)));
        let out = format!("{r401}{r401}{B16_JSON}");
        for size in [1, 64] {
            let mut pieces = AuthWatch::new();
            assert!(out.as_bytes().chunks(size).all(|c| pieces.feed(Stream::Stdout, c) == Verdict::Watching), "chunks of {size}");
            assert!(pieces.retries() == 0 && !pieces.rejected_at_exit(Some(1)), "chunks of {size}");
        }
    }

    /// S8: a session on the measured claude is stopped by B7's result 401 at
    /// once (its exit 1 never comes while the session's stdin stays open),
    /// said once, as `text`; a text 401 on either stream likewise. The two
    /// retries before the result are counted, below the limit.
    #[test]
    fn a_session_on_the_measured_claude_is_stopped_by_its_first_result_or_text_401() {
        let mut w = AuthWatch::for_session(true);
        for i in 0..4 {
            assert_eq!(w.feed(Stream::Stdout, b7_line(i).as_bytes()), Verdict::Watching, "line {i}");
        }
        assert_eq!(w.verdict_how(), None);
        assert_eq!(w.feed(Stream::Stdout, b7_line(4).as_bytes()), Verdict::Rejected, "the result 401");
        assert_eq!((w.verdict_how(), w.retries()), (Some("text"), 2));
        assert_eq!(w.feed(Stream::Stdout, b7_line(4).as_bytes()), Verdict::Watching, "said once");
        for (stream, line) in [(Stream::Stderr, format!("{}\n", b7_text())), (Stream::Stdout, "API Error: 401 nope\n".to_string()), (Stream::Stderr, "  Invalid API key · Please run /login\n".to_string())] {
            let mut w = AuthWatch::for_session(true);
            assert_eq!(w.feed(stream, line.as_bytes()), Verdict::Rejected, "{line}");
            assert_eq!(w.verdict_how(), Some("text"));
        }
        // The retry rule still stops it first when the third retry comes before any result.
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::for_session(true);
        assert_eq!(w.feed(Stream::Stdout, format!("{r401}{r401}{r401}").as_bytes()), Verdict::Rejected);
        assert_eq!(w.verdict_how(), Some("retries"));
        // A turn answered before the 401 does not shield the 401 after it.
        let mut w = AuthWatch::for_session(true);
        assert_eq!(w.feed(Stream::Stdout, format!("{ANSWERED}{REFUSED}").as_bytes()), Verdict::Rejected);
    }

    /// S8: on any other claude (the timers unmeasured), a session is stopped
    /// by the retry rule alone: B7's result 401 says nothing while it runs
    /// (the exit rule still reads an exit 1, should one come), three retries
    /// say it as `retries`.
    #[test]
    fn a_session_on_another_claude_is_stopped_by_the_retry_rule_alone() {
        let mut w = AuthWatch::for_session(false);
        assert!(B7_STREAM.as_bytes().chunks(7).all(|c| w.feed(Stream::Stdout, c) == Verdict::Watching));
        assert_eq!((w.verdict_how(), w.retries()), (None, 2));
        assert!(w.rejected_at_exit(Some(1)), "an exit 1 after it is still the S7 rule's");
        let r401 = retry(401, "authentication_failed");
        let mut w = AuthWatch::for_session(false);
        assert_eq!(w.feed(Stream::Stdout, format!("{r401}{REFUSED}{r401}").as_bytes()), Verdict::Watching);
        assert_eq!(w.feed(Stream::Stdout, r401.as_bytes()), Verdict::Rejected);
        assert_eq!(w.verdict_how(), Some("retries"));
        assert_eq!(AuthWatch::new().verdict_how(), None, "vm exec's watch");
    }

    /// S8: what is never evidence stays nothing for a session on the
    /// measured claude too: each line of `what_never_counts`, B16's valid run
    /// (its `rate_limit_event` line included), a long refused result (passed
    /// over), an error result that only mentions a signature.
    #[test]
    fn a_session_watch_never_stops_on_what_is_no_evidence() {
        let mut lines = vec![
            retry(429, "rate_limit"),
            retry(500, "server_error"),
            "API Error: 403 Forbidden (the proxy)\n".to_string(),
            "Connection error.\n".to_string(),
            "{\"type\":\"result\",\"is_error\":true,\"result\":\"API Error: 500\"}\n".to_string(),
            "{\"type\":\"result\",\"is_error\":false,\"result\":\"API Error: 401 in a quoted answer\"}\n".to_string(),
            "the model said: API Error: 401 is a status code\n".to_string(),
            "{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"the fetch said: API Error: 401\"}\n".to_string(),
            padded(&b7_line(4), "\"terminal_reason\":\""),
            B16_STREAM.to_string(),
        ];
        lines.push(B16_JSON.to_string());
        for line in lines {
            let mut w = AuthWatch::for_session(true);
            assert_eq!(w.feed(Stream::Stdout, line.as_bytes()), Verdict::Watching, "{}", &line[..line.len().min(120)]);
            assert_eq!(w.verdict_how(), None);
        }
    }

    /// AUTH_TIMERS is what `oauth-t1` measured (S7 B11 on claude 2.1.296, S8
    /// part B on 2.1.302, S10 part B on 2.1.305; S11 part B on 2.1.310, its
    /// row the reviewed table's): a changed value comes from a new
    /// measurement, for the version it names.
    #[test]
    fn auth_timers_are_what_oauth_t1_measured() {
        assert_eq!(AUTH_TIMERS, AuthTimers { claude: "2.1.305", oauth_401_wait_ms: 0, refresh_answer_timeout_ms: 30_000, exits_while_stdin_open: false });
        // S11 (L3): the reviewed table, S8 part B's 2.1.302, AUTH_TIMERS, then S11 part B's 2.1.310 (24 Oct).
        assert_eq!(
            AUTH_TIMERS_REVIEWED,
            [
                AuthTimers { claude: "2.1.302", oauth_401_wait_ms: 0, refresh_answer_timeout_ms: 30_000, exits_while_stdin_open: false },
                AUTH_TIMERS,
                AuthTimers { claude: "2.1.310", oauth_401_wait_ms: 0, refresh_answer_timeout_ms: 30_000, exits_while_stdin_open: false },
            ]
        );
    }

    /// S11 (L3): the reviewed versions are sorted oldest first, each once, `AUTH_TIMERS` among them (no longer the
    /// last since 2.1.310 joined); `timers_for` finds exactly them.
    #[test]
    fn the_reviewed_timers_are_sorted_unique_and_hold_auth_timers() {
        let key = |v: &str| v.split('.').map(|p| p.parse::<u64>().unwrap()).collect::<Vec<_>>();
        assert!(AUTH_TIMERS_REVIEWED.windows(2).all(|w| key(w[0].claude) < key(w[1].claude)), "sorted and unique");
        assert!(AUTH_TIMERS_REVIEWED.contains(&AUTH_TIMERS));
        assert_eq!(timers_for("2.1.310").map(|t| t.claude), Some("2.1.310"), "S11 part B's measurement, reviewed");
        for t in &AUTH_TIMERS_REVIEWED {
            assert!(crate::wire::pin::is_version(t.claude), "{}", t.claude);
            assert_eq!(timers_for(t.claude), Some(t));
        }
        for unmeasured in ["2.1.296", "2.1.308", "", "2.1"] {
            assert_eq!(timers_for(unmeasured), None, "{unmeasured}");
        }
    }

    /// AUTH_FAIL_BUDGET_MS covers what S7 B10 measured on the same claude
    /// (179 s of retries before the blocked turn ended), with a margin (S8 L8).
    #[test]
    fn the_auth_fail_budget_covers_b10s_179_seconds() {
        const B10_MS: u64 = 179_000;
        assert_eq!(AUTH_FAIL_BUDGET_MS, 200_000);
        const { assert!(AUTH_FAIL_BUDGET_MS > B10_MS && AUTH_FAIL_BUDGET_MS - B10_MS <= 30_000, "a margin over B10, not a different measurement") };
        assert_eq!(AUTH_FAIL_BUDGET_CLAUDE, "2.1.296", "keyed to the version B10 ran");
    }

    proptest::proptest! {
        /// Any chunking of the same output reaches the same verdicts: one
        /// retry 401, a reply (the count starts again), then three more with
        /// a non-auth retry, a plain line and a text 401 between them, and a
        /// fourth. Rejected is said exactly once, by the chunk that completes
        /// the third line counted since the reply; the counts and the verdict
        /// at exit are those of the whole output read at once.
        #[test]
        fn chunking_never_changes_the_verdict(cuts in proptest::collection::vec(0usize..900, 0..12), stderr_first in proptest::bool::ANY) {
            let r401 = retry(401, "authentication_failed");
            let upto_third = format!("{r401}{ASSISTANT}{r401}hello\n{}{r401}API Error: 401 nope\n{r401}", retry(429, "x"));
            let text = format!("{upto_third}{r401}");
            let bytes = text.as_bytes();
            let stream = if stderr_first { Stream::Stderr } else { Stream::Stdout };
            let mut whole = AuthWatch::new();
            proptest::prop_assert_eq!(whole.feed(stream, bytes), Verdict::Rejected);
            let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (bytes.len() + 1)).collect();
            points.sort_unstable();
            let mut pieces = AuthWatch::new();
            let mut said = Vec::new();
            let mut at = 0;
            for p in points.into_iter().chain([bytes.len()]) {
                let end = p.max(at);
                if pieces.feed(stream, &bytes[at..end]) == Verdict::Rejected {
                    said.push((at, end));
                }
                at = end;
            }
            proptest::prop_assert_eq!(said.len(), 1, "said once: {:?}", said);
            let (from, to) = said[0];
            proptest::prop_assert!(from < upto_third.len() && upto_third.len() <= to, "by the chunk {}..{} that ends the third line at {}", from, to, upto_third.len());
            proptest::prop_assert_eq!(whole.retries(), pieces.retries());
            proptest::prop_assert_eq!(whole.retries(), 4);
            proptest::prop_assert_eq!(whole.rejected_at_exit(Some(1)), pieces.rejected_at_exit(Some(1)));
        }

        /// F5: the same with lines over LINE_MAX, cut anywhere (also right at
        /// a long line's head and at the limit): a retry 401 and a long reply,
        /// twice (each reply starts the count again), then a retry 401, a long
        /// echoed user line (nothing) and two more. Rejected is said exactly
        /// once, by the chunk that ends the last line, with three counted, as
        /// when the whole output is read at once.
        #[test]
        fn chunking_never_changes_a_long_lines_verdict(cuts in proptest::collection::vec(0usize..240_000, 0..12), near in proptest::collection::vec((0usize..9, 0usize..7), 0..4), on_stderr in proptest::bool::ANY) {
            let r401 = retry(401, "authentication_failed");
            let (reply, user) = (padded(ASSISTANT, "\"text\":\""), padded(USER, "\"content\":\""));
            let text = format!("{r401}{reply}{r401}{reply}{r401}{user}{r401}{r401}");
            let bytes = text.as_bytes();
            // Each long line's head and limit, where a cut lands next to them.
            let starts = [r401.len(), 2 * r401.len() + reply.len(), 3 * r401.len() + 2 * reply.len()];
            let edges: Vec<usize> = starts.iter().flat_map(|s| [s + HEAD_MAX, s + LINE_MAX, s + LINE_MAX + 1]).collect();
            let stream = if on_stderr { Stream::Stderr } else { Stream::Stdout };
            let mut whole = AuthWatch::new();
            proptest::prop_assert_eq!(whole.feed(stream, bytes), Verdict::Rejected);
            proptest::prop_assert_eq!(whole.retries(), 3);
            let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (bytes.len() + 1)).chain(near.into_iter().map(|(e, d)| edges[e] + d - 3)).collect();
            points.sort_unstable();
            let mut pieces = AuthWatch::new();
            let mut said = Vec::new();
            let mut at = 0;
            for p in points.into_iter().chain([bytes.len()]) {
                let end = p.max(at);
                if pieces.feed(stream, &bytes[at..end]) == Verdict::Rejected {
                    said.push((at, end));
                }
                at = end;
            }
            proptest::prop_assert_eq!(said.len(), 1, "said once: {:?}", said);
            proptest::prop_assert_eq!(said[0].1, bytes.len(), "by the chunk that ends the last line: {:?}", said);
            proptest::prop_assert_eq!(pieces.retries(), 3);
            proptest::prop_assert_eq!(whole.rejected_at_exit(Some(1)), pieces.rejected_at_exit(Some(1)));
        }

        /// S8: any chunking of B7's stream-json run, on either stream, stops
        /// a session on the measured claude exactly once, by the chunk that
        /// ends its result line, as `text`.
        #[test]
        fn chunking_never_changes_a_sessions_verdict(cuts in proptest::collection::vec(0usize..4096, 0..12), on_stderr in proptest::bool::ANY) {
            let bytes = B7_STREAM.as_bytes();
            let result_at = B7_STREAM.len() - b7_line(4).len();
            let stream = if on_stderr { Stream::Stderr } else { Stream::Stdout };
            let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (bytes.len() + 1)).collect();
            points.sort_unstable();
            let mut w = AuthWatch::for_session(true);
            let mut said = Vec::new();
            let mut at = 0;
            for p in points.into_iter().chain([bytes.len()]) {
                let end = p.max(at);
                if w.feed(stream, &bytes[at..end]) == Verdict::Rejected {
                    said.push((at, end));
                }
                at = end;
            }
            proptest::prop_assert_eq!(said.len(), 1, "said once: {:?}", said);
            proptest::prop_assert!(said[0].1 > result_at && said[0].1 == bytes.len(), "by the chunk that ends the result: {:?}", said);
            proptest::prop_assert_eq!(w.verdict_how(), Some("text"));
        }
    }
}
