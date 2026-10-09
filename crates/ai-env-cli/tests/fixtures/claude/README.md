# claude fixtures (S7 W5)

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
