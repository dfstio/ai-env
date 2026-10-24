# claude fixtures (S7 W5, B7, B16)

`auth-status-logged-out.json` is the pinned shape of `claude auth status
--json` from the MicroVM image's own bundled claude (image/claude.lock), run
with no token and no network (`docker run --network none ... claude auth
status --json`, as uid 1000 with `HOME=/Users/mike`). It is the logged-out
answer: `loggedIn` is false and `authMethod` is `none`. It holds no email,
organisation or account value (claude reports none when logged out).

`tests/docker_exec.rs` pins the top-level key set and `loggedIn` against it
(`l2_claude_auth_status_json_is_logged_out_with_no_network`). Re-pin it from
the image if the key set changes; this is the provisional part-A shape, set
for the current `CLAUDE_VERSION` in image/claude.lock.

`refused-stream-json-2.1.296.jsonl` and `refused-json-2.1.296.json` are
claude 2.1.296's own answer to a refused setup-token, from S7 part B step
B7's first run (11 Oct 2026: a garbage token delivered on fd 3 to a vpc
MicroVM by `vm exec --credential-file`;
`claude -p 'Reply OK' --output-format stream-json --verbose`, then
`--output-format json`; both exited 1). They are the lines that run wrote to
`target/s7/b7-stream.jsonl` and `target/s7/b7-result.json`, cut to the
fields that matter, values and key order as printed (no session, uuid, cost,
usage, path or request id): the init line, the two `api_retry` 401 lines,
the `<synthetic>` assistant line and the error `result` (whose `type` comes
last); the json run printed the same `result` alone. B7's rerun (the GO)
wrote its own lines over both files, the same shape (`retry_delay_ms` 524
and 1247 where these have 507 and 1246): the first run's are kept only
here, trimmed. They hold no token.
`src/bridge/authwatch.rs`'s tests read them (`TEXT_SIGNATURES`, the result
rule, the `api_retry` shape; the stream-json lines joined into one array
also stand in for a refused `--output-format json --verbose` run, a shape
B7 did not run and B16 measured), and `tests/shim_bridge_local.rs` has a
fake claude print them through `vm exec`.

`valid-stream-json-2.1.296.jsonl` and `valid-json-verbose-2.1.296.json` are
claude 2.1.296's own answer with a valid token, from S7 part B step B16
(11 Oct 2026: the valid sealed setup-token through `ai-env run` with a
throwaway config dir, Cursor's bundled claude 2.1.296 on the Mac;
`claude -p "Reply with exactly OK" --output-format stream-json --verbose`,
then `--output-format json --verbose`). They are the lines of
`target/s7/valid-stream.jsonl` and `target/s7/valid-json-verbose.json` cut
as B7's were, and with no message id: the init line; the reply, an
`assistant` line whose first bytes are as printed through its `model`, its
message cut to the keys B7's kept, in their printed order (`model` first),
its text `OK`; the `rate_limit_event` line, its `type` and `status` alone;
and the answered `result`, starting `{"duration_api_ms":`, its `type` after
its `result`. The json run printed its own four messages (its
`permissionMode` and `duration_api_ms` differ) as one array on one line,
ending with a newline. They hold no token. `src/bridge/authwatch.rs`'s tests
read them: the reply's key order, by which the head rule reads a line over
64 KiB, the answered result's order, the `rate_limit_event` line (nothing)
and the `--output-format json --verbose` array, read message by message.

`usage-limit-result-2.1.305.json` is claude 2.1.305's own result for a turn
refused by the account's weekly limit, from S10 part B step B2 (21 Oct 2026:
`make s8-smoke`, its first pass's chat).
It is the line as captured, verbatim, its keys in the alphabetical order the
capture wrote them (the CLI's own order puts `type` last): `api_error`
`usage_limit_reached`, `api_error_status` 429, `is_error` true, and the
CLI's text `You've hit your weekly limit · resets 10am (UTC)`. It names no
`api_error_params`. Its ids (session, message, uuid) are that chat's; it
holds no token. `src/wire/ratelimit.rs` and `src/bridge/authwatch.rs` read
it (a usage limit, never a refusal), and `tests/fakes/claude-v2.sh`'s
`FAKE_USAGE_LIMIT` prints its shape.

`rate-limit-event-2.1.306.jsonl` is claude 2.1.306's own: the two
`rate_limit_event` lines of S10's A1 check (21 Oct 2026,
`target/s8/a1-check.json`, the `accounts[].lines.rate_limit_event` strings
its `--json` wrote, scrubbed there), copied verbatim by a one-line script
that printed nothing (S11, C6). The first is an `allowed` one with both
unified windows (`five_hour` 2 %, `seven_day` 0, an integer) beside the
top-level `resetsAt` and `rateLimitType` (`five_hour`), `overageStatus`,
`overageDisabledReason` and `isUsingOverage`; the second a `rejected` one
(`seven_day`, whose window is at 1, an integer) with both windows. Neither
has a top-level `utilization` or a `surpassedThreshold`. Their times are
unix seconds of 21-24 Oct 2026 and their ids that check's turns'; they hold
no token (`grep -c sk-ant-` is 0, and
`the_real_rate_limit_fixture_holds_no_secret` in
`src/bridge/accounts/usage.rs` runs the scrubber and the built-in
tripwires over them). `src/wire/ratelimit.rs`'s,
`src/bridge/accounts/usage.rs`'s and `src/bridge/accounts/check.rs`'s
tests read them. The two shapes no real line has shown yet, an
`allowed_warning` with both windows and a `rejected` one with none, are
inline JSON in those tests (S10's constructed file, deleted in S11).
