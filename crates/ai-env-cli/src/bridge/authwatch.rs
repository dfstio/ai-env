//! Was the delivered credential rejected? (S7 D6.) A pure watch over a
//! `claude` command's output, used by `vm exec --with-credential` and `vm
//! smoke --with-credential` now and by S8's pump later. It only reads: the
//! output bytes always pass through unchanged, and nothing here decides what
//! reaches the operator.
//!
//! Two kinds of evidence, both from the lines the command prints:
//! - **A retry 401.** A stream-json `system` line of subtype `api_retry`
//!   whose `error` is `authentication_failed` or whose status is 401. Claude
//!   retries those itself; at the [`RETRY_LIMIT`]th since the command's last
//!   progress the watch says [`Verdict::Rejected`] and `vm exec` stops the
//!   command (TERM to its group) instead of letting it retry on.
//! - **A text 401.** A line starting with one of [`TEXT_SIGNATURES`], or a
//!   `{"type":"result","is_error":true}` line whose `result` starts with one.
//!   It counts only when the command then exits 1 ([`AuthWatch::rejected_at_exit`]):
//!   a 401 the command recovered from is no rejection.
//!
//! **Progress clears both**: an `assistant` line that is not an API error
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
//! read as stream-json prints a reply (claude 2.1.288: `type` first, then the
//! API's message, whose `model` comes before its content). It is progress
//! when it starts `{"type":"assistant"` and names a model other than
//! `<synthetic>` before the cut, with no `"error"` there, or starts
//! `{"type":"result"` with `"is_error":false` before the cut. Any other long
//! line (an echoed user message, the init line) clears nothing; the CLI's own
//! error lines are short, and read whole.
//!
//! Never evidence: 429, 5xx, a connection error, the egress proxy's own 403,
//! or a line over [`LINE_MAX`] bytes (its head shows progress, no more). The
//! signatures and the `api_retry` shape are version-pinned and provisional
//! until part B sees a real refusal. No probe records them (the `oauth-t1`
//! row keeps only refresh timings and the result's flags, from which part B
//! sets [`AUTH_TIMERS`]): B7's garbage-token run is the step that sees
//! claude's own words, and its kept output pins them, [`TEXT_SIGNATURES`]
//! from the result text in `target/s7/b7-result.json` and the retry shape
//! from the `api_retry` lines in `target/s7/b7-stream.jsonl` (B16). B14
//! repeats that run as `live_credential_garbage_token_is_refused_with_exit_5`,
//! which prints the same lines.

/// Retry 401s with no progress between them before the command is stopped.
pub const RETRY_LIMIT: u32 = 3;
/// The CLI's own auth timers (S7, the `oauth-t1` probe): how long it waits
/// on a 401 before it asks for a refresh, and before it gives up. "unmeasured"
/// until the part B closing encodes them from the `oauth-t1` row, keyed to the
/// image's claude version; S8's wrapper reads them.
pub const AUTH_TIMERS: &str = "unmeasured";
/// Longest line inspected; a longer one is passed over, its head aside.
pub const LINE_MAX: usize = 64 * 1024;
/// What is kept of a line passed over: its first bytes, which tell a model
/// reply or an answered turn (progress) by how they start (the module doc).
pub const HEAD_MAX: usize = 512;
/// How a refused credential reads in claude's own text (provisional, see the
/// module doc). Matched at the start of a line, after leading whitespace.
pub const TEXT_SIGNATURES: [&str; 3] = ["API Error: 401", "Invalid API key", "OAuth token has expired"];

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
    /// The [`RETRY_LIMIT`]th retry 401 with no progress between them: stop
    /// the command now. Said once, by the chunk that completes that line.
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
    /// A text 401 since the last progress.
    text_401: bool,
    said: bool,
}

impl AuthWatch {
    #[must_use]
    pub fn new() -> AuthWatch {
        AuthWatch::default()
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
            if self.retries >= RETRY_LIMIT && !self.said {
                self.said = true;
                rejected = true;
            }
        }
        if rejected {
            Verdict::Rejected
        } else {
            Verdict::Watching
        }
    }

    /// The command exited with `code`: was it refused? A text 401 with exit
    /// 1, or [`RETRY_LIMIT`] retry 401s with no progress after them and an
    /// exit other than 0 (a command that exits 0 recovered). A last line
    /// without a newline counts too (a long one by its head).
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

    fn line(&mut self, line: &[u8]) {
        let Ok(text) = std::str::from_utf8(line) else { return };
        let text = text.trim_start();
        if starts_with_signature(text) {
            self.text_401 = true;
            return;
        }
        if !text.starts_with('{') {
            return;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return };
        let field = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
        match field("type") {
            Some("system") if field("subtype") == Some("api_retry") => {
                let status = ["error_status", "status"].iter().find_map(|k| v.get(*k).and_then(serde_json::Value::as_u64));
                if field("error") == Some("authentication_failed") || status == Some(401) {
                    self.retries += 1;
                }
            }
            Some("result") => match v.get("is_error").and_then(serde_json::Value::as_bool) {
                Some(true) if field("result").is_some_and(|r| starts_with_signature(r.trim_start())) => self.text_401 = true,
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
    }
}
