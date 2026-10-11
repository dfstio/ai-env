# claude fixtures (S7 W5, B7)

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
claude 2.1.296's own answer to a refused setup-token, from S7 part B step B7
(11 Oct 2026: a garbage token delivered on fd 3 to a vpc MicroVM by
`vm exec --credential-file`;
`claude -p 'Reply OK' --output-format stream-json --verbose`, then
`--output-format json`; both exited 1). They are the lines of
`target/s7/b7-stream.jsonl` and `target/s7/b7-result.json` cut to the
fields that matter, values and key order as printed (no session, uuid, cost,
usage, path or request id): the init line, the two `api_retry` 401 lines,
the `<synthetic>` assistant line and the error `result` (whose `type` comes
last); the json run printed the same `result` alone. They hold no token.
`src/bridge/authwatch.rs`'s tests read them (`TEXT_SIGNATURES`, the result
rule, the `api_retry` shape; the stream-json lines joined into one array
also stand in for `--output-format json --verbose`, a shape B7 did not
run), and `tests/shim_bridge_local.rs` has a fake claude print them through
`vm exec`.
