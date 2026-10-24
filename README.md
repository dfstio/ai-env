# ai-env

**Encrypted `.env` files that stay `.env` — unlocked by Touch ID.**

AI coding agents read files. Ignore files don't stop them — Claude Code has been reported
ignoring both `.claudeignore` and `.gitignore`. An ignore file is a suggestion; encryption is a
boundary. `ai-env` encrypts your `.env` **in place**: the file keeps its name, stays a valid
dotenv file, and parses cleanly in every tool that loads it — but the secrets inside are
age-encrypted to a key in your Mac's **Secure Enclave**. Using them requires **Touch ID**.

```sh
brew install age age-plugin-se
cargo install --path crates/ai-env-cli --locked   # installs ai-env + ai-env-claude; no Xcode needed

ai-env keygen myproject                    # one-time: enclave key + recovery ceremony
ai-env encrypt                             # .env becomes ciphertext, in place — no prompt
ai-env run -- npm run dev                  # Touch ID → runs with the real env
ai-env show                                # Touch ID → prints the plaintext
```

An agent (or anyone) reading the encrypted `.env` sees:

```
# ENCRYPTED .env — ai-env (https://github.com/dfstio/ai-env)
# This file is intentionally encrypted. The secrets are NOT here.
# ...
AI_ENV=1
AI_ENV_VERSION=1
AI_ENV_CIPHER=age-v1
AI_ENV_README="This .env is encrypted by ai-env; secrets require Touch ID. …"
AI_ENV_DATA=YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHAyNTZ0YWcg…
```

Tools that `source` it or load it via dotenv get only harmless `AI_ENV*` metadata — including
`AI_ENV_README`, so even a confused process carries the explanation in its own environment.

## How it works

- **Standard [age](https://age-encryption.org) encryption**, driven through the `age` binary.
  The payload is a whole-file age ciphertext (variable *names* leak nothing), base64 on a
  single unquoted line — validated against `source` (zsh/bash), python-dotenv, node dotenv,
  `node --env-file`, direnv, docker compose, and `docker run --env-file`.
- **The Secure Enclave key** comes from [`age-plugin-se`](https://github.com/remko/age-plugin-se)
  (CryptoKit; no entitlements, no Apple Developer account). The private key never leaves the
  enclave; what's on disk is a device-bound handle, useless on any other machine.
- **Named keys per project/network** (`myapp-mainnet`, `myapp-devnet`, …). Files carry a
  cryptographic *tag* (the `p256tag` stanza), so `ai-env` knows which key opens which file —
  automatically, offline, with **zero** wrong-key Touch ID prompts. `ai-env which .env` tells
  you without decrypting anything.
- **Encryption never prompts** (public-key only; works over SSH, in CI, anywhere). Decryption
  is exactly **one** Touch ID prompt.

## Recovery — read this before you need it

The enclave key dies with the Mac (theft, logic-board repair, erase-and-install). That is why
`ai-env keygen` runs a **recovery ceremony**: it generates a second, software recovery identity,
shows it **once**, and makes you paste it back (proving you saved it — e.g. into Strongbox or
any password manager that syncs off this machine) before the key is committed. Every encrypted
file is addressed to both the enclave key *and* the recovery identity. The recovery secret is
**never written to disk** by ai-env.

**On a brand-new Mac** — no ai-env, no plugin, no Xcode, no keystore, no backup of this machine:

```sh
brew install age
umask 077 && pbpaste > /tmp/recovery.txt      # paste the identity from your vault
grep -m1 '^AI_ENV_DATA=' .env | cut -d= -f2- | base64 -d | age -d -i /tmp/recovery.txt
rm /tmp/recovery.txt
```

That one-liner is also printed in every encrypted file's header. Drill it quarterly:

```sh
ai-env verify-recovery myproject     # paste from the vault; proves it still decrypts
```

`ai-env keys list` shows when each key's recovery was last verified and flags anything >90 days.

**Forgot a key (`keys forget`), migrated Macs, or lost the keystore?** The enclave key is gone
for good — but the recovery identity brings the *workflow* back:

```sh
ai-env keys restore mykey --rekey .
```

One paste from your vault → a **new** Secure Enclave key → every file under `.` that the
recovery identity opens is re-encrypted to it (software-only — zero Touch ID prompts; files
belonging to other keys are skipped untouched). The Strongbox entry stays valid: by default the
pasted identity remains the key's recovery recipient (`--new-recovery` runs a fresh ceremony
instead, for suspected-compromise restores — with `--rekey` it first asks for the OLD identity,
used only to re-encrypt the existing files).

If the key **already exists**, the same command runs in **sweep-only mode**: the paste is
verified against the key's stored recovery recipient (wrong key → refused) and only the
re-encryption sweep runs — the working remedy when old files still exit 4 after a restore
without `--rekey`. A sweep that re-encrypts **zero** files warns loudly: that means the pasted
identity opened nothing and is probably a different key's recovery.

### Sharing with a server or teammate (`keys add-recipient`)

To let another party decrypt — a deploy target's age key (e.g. the per-stack server identity
in AWS SSM), or a colleague — add their **public** recipient to your key:

```sh
ai-env keys add-recipient silvana-mainnet age1xyz… --label "server-mainnet (SSM)" --rekey .
```

The recipient must be the public `age1…` half (from `age-keygen -y`); pasting an
`AGE-SECRET-KEY` private identity is refused before anything is written, input is normalized
to lowercase (bech32 is single-case; age rejects uppercase lines), the label must be a single
line, and after every append ai-env probe-encrypts against the updated file and **rolls back**
if age rejects it — recipients.txt can never be left in a state that breaks encryption.
Adding is idempotent and only affects **new** encryptions — pass `--rekey DIR` to re-encrypt
the key's existing containers too (one Touch ID prompt per file; the count, listing, and >10
confirmation cover only this key's files, and re-running with `--rekey` still sweeps even when
the recipient is already present).

## Commands

```
ai-env keygen NAME [--access-control POLICY] [--strongbox-entry TEXT] [--no-recovery]
ai-env encrypt [FILE] [-k NAME] [--stdout] [--force]      # in place; no prompt
ai-env show    [FILE] [-k NAME] [-i IDENTITY]             # print plaintext (Touch ID)
ai-env decrypt [FILE] [-o OUT | --force]                  # restore plaintext (Touch ID)
ai-env run     [-f FILE] [-k NAME] -- CMD ARGS...         # exec with decrypted env (Touch ID)
ai-env edit    [FILE] [-k NAME] [-i IDENTITY]             # secure in-terminal editor (Touch ID)
ai-env which   [FILE]                                     # which key opens this? no prompt
ai-env info    [FILE] [--json]                            # header details, no prompt
ai-env keys    list | show NAME | default NAME | forget NAME [--yes]
ai-env keys    add-recipient NAME RECIPIENT [--label TEXT] [--rekey DIR] [--yes]
ai-env keys    restore NAME [--rekey DIR] [--new-recovery]   # recreate from Strongbox identity
ai-env rekey   [DIR] [--dry-run] [--yes]                  # re-encrypt containers under DIR
ai-env verify-recovery NAME                               # the quarterly drill
ai-env doctor [--json]                                    # environment + repo health check (exit 1 on any [NO ] row);
                                                          #   its AWS rows only under ai-env as: ai-env as ops -- ai-env doctor
ai-env gates  [--json] [--only G1,G3] [--out FILE]        # MicroVM bridge pre-code gates → plans/gates.md (bridge feature);
                                                          #   --only re-measures a subset: nothing is written, go/no-go is not evaluated;
                                                          #   G2 and G7 run as the operator, G7 simulating ai-env-deployer and ai-env-ops
ai-env wrapper install [--write] [--permission-mode M] [--mode passthrough|remote]   # point Cursor's claudeProcessWrapper at the sibling
                                                          #   ai-env-claude; --mode also sets [wrapper].mode in bridge.toml (S8)
                                                          #   (dry run unless --write; backs up settings.json, and bridge.toml with --mode; bridge feature)
ai-env wrapper status [--json]                            # is Cursor's wrapper set, which ai-env-claude, the effective mode and
                                                          #   roots, a remote session's start checks, the extension Cursor last ran and
                                                          #   each open window's (read-only: no AWS, no Touch ID; exit 1 on a [NO ] row)
ai-env wrapper uninstall [--write]                        # take claudeProcessWrapper out of Cursor's settings (dry run unless
                                                          #   --write; backs up settings.json; initialPermissionMode and bridge.toml stay;
                                                          #   it warns first while remote chats keep only their view here, S9)
ai-env wrapper census [--last N] [--json] [--record-probes]  # invocation shapes the wrapper recorded (bridge feature)
ai-env wrapper settings-sync UUID [--rule R]… [--all-safe] [--write] [--image-dir DIR]   # a remote chat's approved rules → the image (S8)
ai-env session list [--json] | show UUID [--json] [--settings-diff] | forget UUID... [--purge] | drop-transport UUID   # sessions the wrapper registered (bridge feature); drop-transport: the reattach check (S8);
                                                          #   forget: several ids, every one checked first, one Touch ID for --purge (S10)
ai-env session migrate UUID [--json]                      # a remote chat to a new VM now: its running wrapper moves it between turns,
                                                          #   else this command does (S10; one Touch ID either way)
ai-env session stage UUID [--warm] [--json] | sync UUID [--json]   # a chat begun on this Mac into S3, its view left / a remote chat's
                                                          #   transcript from its VM to S3 now (S9; one Touch ID each; --warm adds vm warm's and restores the chat into its VM)
ai-env session gc --remote [--older-than DAYS] [--yes] [--json] | migrate-s9 [--yes] [--json]   # the S3 transcripts of chats closed over
                                                          #   DAYS (90) ago / S8's mirrors into S3 (S9; without --yes: the list only)
ai-env infra  scan DIR [--profile image|repo] [--json]    # secrets + unsafe-settings scan of an image tree; exit 9 on a finding
ai-env infra  pin [--manifest FILE | --check-bundle | --bundle-version] [--lock FILE]  # image/claude.lock from a release manifest; lock vs Cursor bundle; the bundle's version
ai-env infra  status [--write] [--stack dev] [--cwd infra]          # Pulumi outputs + a live image read → bridge.toml [aws] + state/infra.toml
ai-env infra  base-image [--name al2023-1] [--version 1]  # the pinned managed base image is AVAILABLE
ai-env infra  versions-diff --before F --after F [--record-probe]   # image versions around a deploy (bridge feature)
ai-env claude status [--json] | admit [VERSION] [--redo] [--json] | stage [VERSION] [--force] [--json] | update [VERSION] [--json]   # the Claude Code
                                                          #   versions VMs follow (S11): phases, no Touch ID / admit: signature, binary, markers,
                                                          #   Docker tests, no Touch ID / stage in S3 through a credential-less VM, one Touch ID / both
ai-env claude forget VERSION [--local] [--force] | gc [--yes] [--json]   # one version's S3 object (one Touch ID), binary and record /
                                                          #   keep the 3 newest staged, the bundle's and the live windows' (--yes: one Touch ID)
ai-env audit  tail [-n N] [-f] [--session UUID] [--vm ID] [--event E,…] [--actor cli|wrapper|panel] [--since WHEN] [--where K=V]… [--json] | grep PATTERN [-i] [the same filters] [--json]
                                                          #   audit.jsonl's rows, followed with -f / holding a fixed string, exit 1 when none (S11; no AWS, no Touch ID)
ai-env cost   [--since WHEN] [--until WHEN] [--by day] [--json] [--compare FILE]   # the MicroVMs' and the proxy's cost rebuilt from the audit,
                                                          #   a range; --compare judges it against Cost Explorer's (S11; no AWS, no Touch ID)
ai-env panel  serve [--port N] [--bind 127.0.0.1]        # the local control panel on 127.0.0.1, its URL holding this run's bearer; one Touch ID
                                                          #   per action ([panel] enabled = true in bridge.toml; S11)
ai-env creds  aws-set [--user ai-env-runtime|ai-env-ops] [--check] [--force]   # seal `aws iam create-access-key` JSON from stdin:
                                                          #   ai-env-runtime's into credentials/aws.env, ai-env-ops' into credentials/ops.env
ai-env creds  aws-verify [--user ai-env-runtime|ai-env-ops]   # one Touch ID: the sealed key alone must answer as its user (retried while IAM propagates)
ai-env creds  deployer-key [--account ACCOUNT] | deployer-key --clipboard-check   # create-access-key's JSON on stdin → the deployer's
                                                          #   Strongbox entry through this Mac's concealed clipboard, pasted back, checked;
                                                          #   never stored here / only a marker, which must not paste on another Apple device
ai-env creds  setup-token [--stdin|--from-env] [--no-combined] [--force]   # seal the active Claude account's setup-token anew (asked for hidden) (S7)
ai-env creds  account add NAME [--stdin|--from-env] [--use] [--force] [--note TEXT]; rename OLD NEW; note NAME [TEXT]; use NAME; list [--json]; forget NAME [--yes]; check [NAME…] [--json] [--model M]   # Claude
                                                          #   accounts (A1): seal one (one Touch ID) / make it the active one (no Touch ID) / list them /
                                                          #   delete one / one turn each on this Mac's claude: 5-hour and weekly usage (a Touch ID each)
ai-env creds  status [--json] [--unseal] | forget [--yes] [--ops]  # what is sealed, without Touch ID / delete the token, its copies and every account
                                                          #   (--ops: only credentials/ops.env and its backups; the IAM commands are printed)
ai-env vm     images [--managed] | list [--all] | status ID | health ID   # MicroVMs of the ai-env image (bridge feature);
                                                          #   list (without --json) then reconciles the registry locally, as run and smoke do (S10)
ai-env vm     run [--workspace PATH] [--max-duration S] [--egress internet|vpc] [--shell] [--json] …
ai-env vm     token ID [--port 8080|8082|9418] [--minutes M] [--reveal]   # the value only with --reveal
ai-env vm     suspend ID | resume ID | terminate ID|--all [--yes] | gc [--yes] [--include-orphans AGE]
ai-env vm     shell ID [--auth header|subprotocol]         # experimental: the platform shell (VM started with --shell)
ai-env vm     smoke [--max-duration 900] [--keep] [--exec [--with-credential]] [--json]   # run → RUNNING → /health (→ exec checks → a credentialed claude -p) → terminate, with timings
ai-env vm     exec ID [--cwd P] [--env K=V]… [--detach-grace S] [--with-credential | --credential-file P] [--deliver fd|env] -- CMD ARGS…   # run as the agent over /agent; stdio byte-exact, the command's exit status (S6; the credential S7)
ai-env vm     warm WORKSPACE [--json] [--dry-run]          # start the workspace's VM, seed it (S8) and deliver the sealed setup-token, ahead of time (S7);
                                                          #   S11: also stages the bundle's admitted Claude Code and fetches it into the VM
ai-env vm     attach ID --spawn UUID [--from-seq N]       # reattach to a running command (the newest client wins)
ai-env vm     health ID --detail [--json]                  # /health/detail with the session bearer: guard, sockets, spawns, listeners
ai-env box    seed [WORKSPACE] [--branch B] [--no-wip] [--replace] [--dry-run] [--max-mib N] [--json]   # the checkout into its VM at the same path (S8)
ai-env box    fetch [UUID|WORKSPACE] [--wip|--smart-http] [--dry-run] [--max-mib N] [--json]   # the VM's commits and snapshots → refs/remotes/box/* (S8;
                                                          #   --smart-http: git smart-HTTP v2 through the endpoint, S9)
ai-env box    review REV [--base REV]… [--repo DIR] [--json]   # what a push of REV would carry, reviewed; exit 9 on a finding (S9; no AWS, no Touch ID)
ai-env box    hook-install [REPO] [--dry-run] [--json]    # the pre-push hook that reviews every push (S9; never over another hook)
ai-env lab    list | show PROBE | run PROBE [ID] [--log FILE] [--manual VERDICT]   # probes → lab/probes.jsonl
ai-env egress status [--json] | env [--shell] | reload [--if-changed]   # S5 operator commands, as ai-env-ops (see Identities; bridge feature)
ai-env egress allow SLUG HOST [--remove] | suspend HOST [--restore]    # per-workspace extras (global on the proxy; allow: the deployer only) / the kill switch
ai-env egress check [--vm ID] [--keep] [--json] [--if-needed]          # from a vpc VM: direct egress and DNS closed, the allowlist working, S3 for
                                                          #   the transcripts bucket alone (S9) → state/egress-verified.toml
ai-env proxy  stop [--yes] | start | patch                             # the squid instance (stopped: no vpc VM has egress), as ai-env-ops
ai-env as     deployer|ops|root|ambient [--account ACCOUNT] -- CMD ARGS...   # run CMD as one AWS identity, the marker AI_ENV_BRIDGE_AS set (Identities)
ai-env as     --check deployer|ops|root|ambient                # make's guard: exit 0 when this process already runs as it, else 9
ai-env shim   --claude PATH [--app-port 8080] …           # VM mode: MicroVM image entrypoint (shim feature)
ai-env-claude <realBinary> <claude args…>                 # Cursor's claudeProcessWrapper target (bridge feature); a first argument
                                                          #   that is empty, starts with - (but --version, -V, --help or -h alone: exit 0)
                                                          #   or is a bare name but claude: its usage, exit 2 (S9)
```

Exit codes: `0` ok (broken pipes too) · `1` error · `2` usage · `3` cancelled at the prompt (or a
Ctrl-C during `lab run`, once the probe's VMs are ended) · `4` no key opens this file · `5` auth
unavailable (plugin missing, no GUI session, AWS credentials unavailable) · `6` corrupt or plaintext
file where a container was expected · `7` AWS/infra API failure · `8` MicroVM terminal or transport
lost · `9` policy refusal (tripwire, egress gate, workspace outside the approved roots, a review
finding or a refused push, a local resume of a remote chat's view). `vm exec`
exits with the remote command's own status (128 + N when a signal killed it; 127 when the VM has no
such program, 126 when it cannot run it and 1 when the working directory cannot be made, each with an
`ai-env: vm exec:` line); its own failures keep 7/8/9 (with a credential also 3, 4 and 5: see
Credentials) and print an `ai-env:` line (9 also when the VM already runs 8 commands), and a
credentialed `claude` whose delivered token Anthropic refuses ends with 5 and such a line instead of
its own status. No stop signal after the refusal changes that 5. The line is the last write to
stderr: a signal that cuts the last output short leaves it a second more, and a stderr nobody reads
gets none. After SIGTERM or SIGHUP it exits 143, after a Ctrl-C before the command started (or a
second one while the connection is down) 130, and after a closed stdout 0, whatever the command did.

`ai-env doctor` exits `1` when any row is `[NO ]` and `5` when AWS refuses the key of the identity it
runs under; every row is printed first. Rows marked `[-  ]` (not configured yet) and `[!! ]` (warnings)
never change the exit code. Doctor never unseals a key: its AWS rows run only under an identity
`ai-env as` declared, so `ai-env as ops -- ai-env doctor` (one Touch ID) is the full check (see
Identities).

### The Cursor wrapper (stages S1–S2)

`ai-env wrapper install --write` writes two user settings, `claudeCode.claudeProcessWrapper`
(the absolute path of the `ai-env-claude` next to `ai-env`) and `claudeCode.initialPermissionMode`
(default `default`, i.e. the mode Cursor labels Manual; with a wrapper configured the extension
always passes `--permission-mode` explicitly). It backs up `settings.json` first, keeps comments
and key order, prints the exact snippet when it cannot write, and writes nothing when both keys
already hold their values (`settings: nothing to write`). Cursor reads the setting each time
it starts a process: the chats it starts afterwards use the wrapper, and a chat already open keeps
its process until that ends (a window reload restarts the open chats through the wrapper).
`ai-env wrapper status` shows whether the setting is there, which `ai-env-claude` it names, the
effective mode and the extension version Cursor last ran, without AWS or Touch ID;
`ai-env wrapper uninstall --write` takes the setting out again (backup first;
`initialPermissionMode` and bridge.toml stay), and the `undo:` line it prints puts it back
(`ai-env wrapper install --write`, plus `--permission-mode` when install would otherwise change
`initialPermissionMode`).
Every invocation the wrapper handles — chat sessions, config probes, `auth status --json`,
`plugin list --json`, `mcp add` … — execs the bundled binary locally and appends one redacted
JSON line to `~/.config/ai-env/bridge/logs/census.jsonl` (environment variable NAMES, a short
allowlist of non-secret values, argv with MCP credentials and the positional tail after `--`
masked). `ai-env wrapper census` prints it; `--record-probes` writes the `entrypoint` and
`stock-ext-oauth` verdicts (from the newest session row) and, once the census holds remote end rows
(S8), `init-wrapper` (the newest cold and warm ones: on a VM started for the session, against 30 s;
on one reused, against 5 s; on one resumed, against 8 s (since S10); a session that moved the chat, a
reopen's carry included, is judged only past 30 s, as the cold row, and never a pinned chat's) to
`lab/probes.jsonl`. It exits 1 after writing when a verdict misses its expectation, a `gap:cold` or
`gap:warm` included: after the first cold chat alone it reads `gap:warm` (or `over:cold`).
`AI_ENV_BRIDGE_LOCAL=1` in the extension's environment is the kill switch: exec the real binary, no
census, no bridge.

With `AI_ENV_BRIDGE_MODE=local-child` (or `local-scratch`) in `claudeCode.environmentVariables`,
a stream-json chat session is no longer exec'd: the wrapper spawns the bundled binary as a piped
child with `--session-mirror` appended and stands between it and the extension (stage S2, no AWS).
Everything else — every subcommand, `--version`, and every session while neither the variable nor
`[wrapper] mode` (S8, below) asks for another mode — still execs exactly as above. The pump:

- peels the child's `transcript_mirror` frames (never forwarded) and, when
  `AI_ENV_BRIDGE_MIRROR_ROOT` is set or the child uses another config dir, appends their entries
  byte-for-byte under the same relative path (0600 files, 0700 directories, no symlinks); claude
  2.1.301 and later write their `api-request`, `api-request-shape` and `api-request-blob` records to
  their own file only, never to a frame, so the copy lacks them (T2.5 compares the copy with
  `grep -v '"type":"api-request'` of the real file, not the raw file);
- records the extension's `initialize` and state requests (permission mode, `apply_flag_settings`,
  MCP servers, …) and replays them into a respawned child without the extension noticing;
- `local-scratch` runs the child with its own `CLAUDE_CONFIG_DIR` under
  `~/.config/ai-env/bridge/state/scratch/`, seeds it with the Mac transcript before `--resume`, and
  retries once when the child reports `No conversation found with session ID:`;
- `local-scratch` also logs that child in (S7), since it has no login of its own: a
  `CLAUDE_CODE_OAUTH_TOKEN` in the extension's environment is passed on; otherwise the sealed
  setup-token is unsealed before the child starts, one Touch ID per piped invocation (Cursor's config
  probe, whose arguments are a chat's, included), with the countdown on the wrapper's stderr starting
  from 50 s at most (Cursor's 60 s `initialize` window minus 10 s), whatever `[creds].unseal_timeout_s`
  says above that. The token reaches the child on fd 3 (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3`),
  or in its environment with `[creds] deliver = "env"`; a scratch child never inherits a
  `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`. The wrapper drops its copy once the child is spawned, or,
  for a `--resume`, at most 2 s after the child answered `initialize` (its one seed retry may need it),
  unless the child reported a resume miss or exited by then: the copy then goes once the seed retry's
  respawn has it, or when the session ends.
  No sealed token, a refused one (or a `state/creds.toml` that cannot be read, which may record a
  refusal), a dismissed dialog or the deadline gives one note line and a logged-out child, never a
  failed session; a signal during the wait closes the dialog and ends the wrapper (130 for Ctrl-C, 143
  for SIGTERM and SIGHUP). The unseal is audited `credential_unseal`, and
  the census end row notes `credential:` with `fd`, `env`, `inherited` or `none` (how the generation
  that served the session was logged in: `none` when the seed retry respawned the child after the
  copy was dropped);
- writes `logs/wrapper.log`, a second census row with `end`/`exit` (`ai-env wrapper census` shows
  `exit=… dur=…`), `audit.jsonl` rows for retries, and one `state/sessions/<uuid>.toml` per chat
  (`ai-env session list|show|forget`; rows hold digests and a summary, never request bodies);
- exits within 1.5 s of the extension closing stdin (SIGTERM at +0.8 s, SIGKILL at +1.2 s) and
  within 1 s of a SIGTERM.

Debug builds also honour the lab knobs `AI_ENV_BRIDGE_LAB_EXIT=<code>:<msg>:after-init`,
`AI_ENV_BRIDGE_LAB_IGNORE_EOF=1|2`, `AI_ENV_BRIDGE_LAB_STDOUT_NOISE=1`,
`AI_ENV_BRIDGE_LAB_DELAY_INIT_MS=<n>`, `AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS=<n>` (the replay deadline
of a respawned child: n ms in place of 15 s), and from S7 `AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS=<n>`
(once the session is initialized the pump sends the extension one `oauth_token_refresh` request of
its own, waits at most n ms, never forwards the answer, and records its class in the end row as
`synthetic_oauth:<class>`, which `ai-env wrapper census --record-probes` puts in the
`stock-ext-oauth` row's note) and `AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS=<n>` (the `local-scratch`
unseal's budget in ms, in place of `[creds].unseal_timeout_s`; the same knob budgets a credentialed
`vm` or `lab` command's unseals: see Credentials). All are compiled out of release builds, and the
live make targets drop every lab knob (`LAB_UNSET`); only `make test-aws SLOW=1` then sets one again,
S9's `AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2`, for its test process (stage S9).

### The MicroVM image and its infrastructure (stage S3)

`image/` holds everything the MicroVM image is built from, and `image/MANIFEST` lists it:
`make image-zip` cross-builds the shim (`make vm-build`), copies exactly the listed files into
`target/image/stage` with the listed modes (an unlisted file stops the build), scans the staged tree
with `ai-env infra scan` (built-in tripwires for API keys, private keys, age identities, JWTs and
URL credentials, plus rules for the baked Claude settings: no `bypassPermissions`, no broad allow
entries, no secret-named `env` keys; exit 9 names file, line and rule, never the matched text), and
writes a deterministic zip plus `target/image/image.json` (its sha256 and S3 key). The image pins
Claude Code by version, size and SHA-256 (`image/claude.lock`; `make claude-pin CLAUDE_VERSION=<v>`
refreshes it from the release manifest, whose signature gpgv checks against the vendored release
key in `crates/ai-env-cli/certs/`, fail-closed) and bakes a fresh, reviewed config subset — never
the Mac's own `~/.claude`. That claude is the image's fallback: the Cursor extension updates itself,
often daily, and from S11 the VMs follow its Claude Code with no deploy (`ai-env claude update`,
below); the deploy's preflight P10 notes a bundle that differs from the lock (`[-  ]`) and refuses
nothing for it.

`ai-env shim` is the image's ENTRYPOINT. As PID 1 it is a small init (child subreaper, signal
forwarding, orphan reaping) that runs the same binary as its worker; the worker serves the
platform hooks on 9000 (`/ready` waits for the listeners and one `claude --version`; `/validate`
checks the version against the lock, the settings files, that no build-time state leaked into the
snapshot and, from S6 (V6), the peer guard itself, and answers 409 without checking once a `/run`
was accepted; `/run` is first-wins and fail-closed without a payload), `/health`, `/agent` and the
bearer-only `/health/detail` on 8080, and a bearer-only side port on 9418. It logs where every hook
request comes from; from S6 the image runs `--hook-source peer` (see "Agent transport"), and it
measures the clock without stepping it (`--clock forward` needs CAP_SYS_TIME, which the image does not
grant).

```sh
make image-zip                 # vm-build + stage + scan + zip
make test-docker               # the shim in the base image (L1) and the built image (L2), then `vm exec` on L2; stamps the zip
make s3-preflight PHASE=a      # build-side preconditions, one row each; P11 runs ai-env infra base-image, an operator command:
                               #   an agent in its own account: ai-env as ambient -- make s3-preflight PHASE=a;
                               #   on this Mac: ai-env as ops -- make s3-preflight PHASE=a
make check-policies preview-scratch   # IAM Access Analyzer + a throwaway-backend Pulumi preview (read-only; this shell's own
                               #   credentials, an agent's; on this Mac: ai-env as ops -- make check-policies, and
                               #   ai-env as deployer -- make preview-scratch, whose program reads the AMI parameter)
make deploy                    # (deployer: one paste, after the zip is built and the stack's passphrase, one Touch ID unless
                               #   set; the bootstrap as the account root) Pulumi up of infra/ in eu-central-1, then waits for
                               #   the image build
make infra-status WRITE=1      # (ops: one Touch ID) stack outputs (+ the image's live state) → bridge.toml [aws] (comments kept)
                               #   + state/infra.toml
make runtime-key               # (deployer: one paste) seal a key of the ai-env-runtime user under the bridge keystore key,
                               #   rebuild every Claude account's combined.env (one Touch ID each), then verify the key (one
                               #   Touch ID); ROTATE=1 replaces it
make claude-update             # retired (S11): exits 2 naming ai-env claude update; VMs follow Cursor's claude with no deploy
```

**Claude Code versions.** `make claude-update` is retired (S11): it prints `claude-update: retired
(S11): …` and exits 2. A new Claude Code version needs no deploy: a chat's VM runs the version of the
Cursor extension that started the chat once ai-env has admitted and staged it, and the image's own
claude (the lock) until then (`ai-env claude status`; stage S11, below). `make claude-pin` still
moves the image's fallback, which takes a deploy; no daily update needs one.

Pulumi state stays in a local backend on the deploying Mac; `infra/Pulumi.dev.yaml` and
`infra/config/dev.env` (budget email and limit) are not committed — copy the `.example` files. No
secret ever enters Pulumi config, outputs or state. Pulumi creates the three IAM users
(`ai-env-runtime`, `ai-env-deployer`, `ai-env-ops`) and their rights, never an access key (an
`aws.iam.AccessKey` would write its secret into the state; the stack's guard and plan check refuse
one). Each key is created out of band, `aws iam create-access-key` piped straight into ai-env: the
runtime user's by `make runtime-key` into `ai-env creds aws-set`, sealed to
`~/.config/ai-env/bridge/credentials/aws.env`; ai-env-ops' by `make ops-key` (the first one by
`make operator-keys`) into `ai-env creds aws-set --user ai-env-ops`, sealed to
`credentials/ops.env`; ai-env-deployer's by `make operator-keys` (later
`make deployer-key ROTATE=1`) into `ai-env creds deployer-key`, which hands it over to its
Strongbox entry and writes it to no file (see Identities, below).

### MicroVM lifecycle (stage S4)

`ai-env vm` starts, inspects and stops MicroVMs of the image S3 deployed. Every command that talks
to AWS unseals the runtime principal's key from `credentials/aws.env` in-process (one Touch ID per
command; `[aws] credentials = "profile:<name>"` reads that one profile instead, a mode refused with
exit 1 under `ai-env as deployer` or `ai-env as ops`, which hide `~/.aws` from their commands) and
never hands it to a child process. The region, the control-plane URL and the TLS policy (TLS 1.3 to
the MicroVM endpoint, Amazon Root CA 1–4 only, proxy variables ignored) are pinned in code;
`AWS_REGION`, `AWS_ENDPOINT_URL*`, `AWS_PROFILE` and `~/.aws/config` cannot move them.

- `vm run` always passes an idle policy (`[vm] max_idle_s`, `suspended_s`, `auto_resume`), resolves
  the image version live (`active` = the latest SUCCESSFUL/ACTIVE), writes a pending row under
  `state/vms/` before `RunMicrovm` and waits for RUNNING (60 s; a VM that does not get there is
  terminated). Without an egress connector (S5) it needs an explicit, audited `--egress internet`;
  `vm smoke` and `lab run` imply it for the VMs they start without a credential. Those that deliver
  one (`vm smoke --exec --with-credential`, the S7 probes `fd-delivery` and `init-budget`) start a
  vpc VM: a credential never enters an internet one.
- `--workspace PATH` holds `state/workspaces/<slug>.lock` until the VM is RUNNING and reuses the
  workspace's VM when its image, egress and shell setting match and enough wall time is left;
  `[vm] max_concurrent` is counted across workspaces (ListMicrovms ∪ the registry) under
  `state/vms.lock` — over the limit is exit 9.
- MicroVMs cannot be tagged: ownership is the image filter plus the `owner` the VM's `/health`
  reports (from the run-hook payload). `vm gc` reports (default), `--yes` terminates expired
  registry VMs, adopts crashed runs and clears stale rows, `--include-orphans AGE` also terminates
  your own row-less VMs; another owner's VM is never touched, a SUSPENDED one never probed.
- Endpoint tokens are scoped to one port (8080, 8082 or 9418), live 1–60 minutes and are shown only
  by `vm token --reveal`. The session token in a VM row (0600) is never printed.

`ai-env lab run` records the platform probes in `lab/probes.jsonl`: `payload-size`,
`no-traffic-before-run`, `snapshot-uniqueness` and `idle-policy-limits` start (and always
terminate) their own short VMs; `hooks-port`, `hooks-source-ip`, `runtime-env`, `disk-budget` and
the second pass of `snapshot-uniqueness` read a runtime log (`make logs SINCE=30m > FILE`, then
`--log FILE`; the shim logs one `ai-env: run-report` line after `/run` and at `/terminate`);
`cloudtrail-payload ID` asks AWS as the operator, ai-env-ops (one Touch ID, none under `ai-env as`;
see Identities), within 7 days of the VM's end while its row exists: RunMicrovm is a CloudTrail data
event (resource type `AWS::Lambda::MicrovmImage`, off by default, never in event history). It checks
the trails and the CloudTrail service-linked channels of eu-central-1 — CloudWatch's CloudTrail
ingestion runs through one, as does Security Lake. A trail or
CloudWatch channel that takes RunMicrovm → the probe prints how to fetch the record (the trail's S3 log
file, or an `aws logs filter-log-events … --unmask` command per log group) and reads it with `--log FILE`
(raw or OCSF CloudWatch records; a CloudWatch copy may be transformed, the row notes where it came from);
another service's channel → read it there and record with `--manual`; nothing → it prints the
`--manual not-logged` command to run once you have confirmed what it cannot see (CloudTrail Lake event
data stores, channels homed in other Regions, organization-level CloudWatch or Security Lake). It never
records a verdict for what it could not see. ai-env-ops holds what the probe needs:
`cloudtrail:DescribeTrails`, `GetEventSelectors`, `ListChannels`, `GetChannel` and
`logs:DescribeLogGroups`. Reading a CloudTrail log group is the deployer's: it holds
`logs:FilterLogEvents` and `logs:Unmask` on the log groups whose name holds `cloudtrail`, which ops
does not (every such group holds the whole account's API record). So the printed
`aws logs filter-log-events … --unmask` command for a group of this account starts with
`ai-env as deployer --` (one paste; a bare `aws` has no credentials of the stack's account on this
Mac), or with the runner the probe ran under when that was `ai-env as ambient` (an agent's session
in another account, where the stack's deployer does not exist) or `ai-env as root`; its redirect and
the `ai-env lab run … --log` after it run as printed. An organization trail's group belongs to
the account that owns the trail: its command is printed without the runner, to run with credentials
of that account.

```sh
make test-aws-readonly         # part A, this shell's own credentials (an agent's account; no runner): TLS to the MicroVM proxy,
                               #   managed images, ListMicrovms, GetMicrovm (read-only)
make s4-smoke                  # T4.1: three `vm smoke --max-duration 900 --json` passes → target/s4/smoke.jsonl
make test-aws [SLOW=1] [PROBES=1]   # the live suite (+ the 6-minute token-expiry test, + re-recorded probes)
```

Debug builds also honour `AI_ENV_BRIDGE_LAB_FAKE_API=<file.json>` (a file-backed fake control plane
and endpoint shared by processes), `AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL=1` and
`AI_ENV_BRIDGE_LAB_BACKOFF_MS=<n>`; an active knob is announced on stderr, and every `--json` record
says `"backend":"fake"` (the fake API) or `"backend":"sdk+knobs"` (the real service with another
knob) instead of `"sdk"`. The live Makefile targets drop all three; `make s4-smoke` accepts only `"sdk"`.

### Egress allowlist (stage S5)

`--egress vpc` VMs get the stack's network connector `ai-env-egress` (the default once
`make infra-status WRITE=1` wrote `[aws] egress_connector_arn`). Its subnet, 10.42.1.0/24 of a dedicated
VPC, has no route but `local`; its security group allows only TCP 3128 to the proxy's address and its
network ACL only that and the replies. The one way out is a squid proxy (t4g.nano, 10.42.0.10) that
tunnels CONNECT to port 443 of exactly the allowlisted hosts — the stack's `allow` list plus
per-workspace extras, minus suspended hosts — and refuses everything else: plain HTTP, other ports, IP
literals, names that resolve to private, loopback or link-local addresses, clients outside the VM
subnet. The VPC has no Amazon DNS (`enableDnsSupport` off; DHCP hands out public resolvers that only
the proxy may reach), so a VM resolves nothing itself; its tools go through the proxy
(`ai-env egress env` prints `https_proxy` and friends). The only DNS a VM reaches is the platform's
`fd00:ec2::253`, which answers locally with an empty reply and sends nothing out (measured with a
canarytokens and an interactsh test). Every VM reaches squid from the connector's one network interface
(10.42.1.158), so squid cannot tell VMs apart. The connector's operator role is trusted by
`lambda.amazonaws.com` only (the principal CloudTrail showed), and an inline Deny confines AWS's managed
operator policy, which allows interfaces in any subnet with any security group, to the VM subnet and the
VM security group (`make check-policies` simulates both sides; `make connector-probe` proves interfaces
still get created).

- **Echo gate.** A VM must echo exactly the connectors its egress requires (`vpc`: the configured
  connector; `internet`: exactly `INTERNET_EGRESS`) when RunMicrovm answers, when it is RUNNING, on
  reuse and on adoption. Anything else is terminated, audited `vm_egress_mismatch` and exit 9. Rows
  record the verdict (`egress_gate`); `vm gc --yes` gates again every live row not marked `passed`.
- **Proxy config** lives in the SSM parameters `/ai-env/proxy/{squid.conf,allow,extras,suspended}`,
  never in user data. `ai-env-proxy-reload` on the instance validates every line, `squid -k parse`s
  the staged config, swaps it in with `squid.conf` last, restarts squid when a host leaves the set (open
  tunnels close) and rolls back on any failure; squid never starts on the package's default config.
  What runs on the instance comes only from three fixed SSM Command documents the stack creates from
  `infra/proxy/documents/`: `ai-env-proxy-reload` (one parameter, `mode`: `apply` or `if-changed`),
  `ai-env-proxy-status` and `ai-env-proxy-patch`, each sent at `--document-version $DEFAULT`.
  `AWS-RunShellScript` is never sent, and IAM lets ai-env-ops and ai-env-deployer send these three
  and nothing else, to the proxy instance only. A `state/infra.toml` that names other documents than
  this ai-env sends stops the commands with exit 1 (update ai-env, or `make infra-status WRITE=1`).
- **Operator commands** (`ai-env egress …`, `ai-env proxy …`) call the `aws` CLI as ai-env-ops
  (region and endpoint pinned; the account must be the connector's): the key of the `ai-env as`
  runner, else `credentials/ops.env` (one Touch ID per command), never the shell's own AWS settings
  (see Identities). They read the stack's ids from `state/infra.toml`:
  `egress allow SLUG HOST [--remove]`, `egress suspend HOST [--restore]` (a concurrent
  write is detected after the fact from the parameter's version, never prevented; any failure after a
  removal says `STILL ALLOWED on the proxy` and exits 7; an AWS service host (`amazonaws.com`,
  `amazonaws.com.cn`, the `.aws` domain) is refused with exit 9, and one already listed shows as drift in
  `egress status`: a VM reads its execution role's keys from IMDS, and those keys work at AWS endpoints
  and nowhere else; S9's transcripts bucket is the one AWS host the stack's own `allow` list holds, see
  "S3 through the proxy"), `egress reload [--if-changed]`, `egress status` (connector, ENIs, routes,
  security groups, NACL, VPC DNS and DHCP, no endpoint but S9's S3 gateway endpoint on the proxy's route
  table, no NAT, peering or IPv6, the transcripts bucket's settings, the proxy serving exactly the
  parameters the stack rendered; any drift is exit 1), `egress env` (no AWS call), `proxy stop|start|patch`.
  `egress allow` (adding or `--remove`) writes `extras`, which widens what every vpc VM may reach, so
  it needs the deployer: as ai-env-ops it is refused before any Touch ID or AWS call (exit 9, naming
  `ai-env as deployer -- ai-env egress allow SLUG HOST`), and IAM denies ai-env-ops that write anyway.
  `egress suspend` and `--restore` stay ai-env-ops' (`suspended` is the one parameter it may write).
  An `AccessDenied` from a proxy document ends with
  `(only ai-env-ops and ai-env-deployer may send the proxy documents: run it under ai-env as ops --)`.
- **`egress check`** starts its own `--egress vpc --shell` VM and runs, through the platform shell,
  curl and dig cases: direct egress and DNS must be closed, the allowlist must answer (401 from the API)
  and refuse the rest; since S9, S3 must take our transcripts bucket alone (seven more cases, 34 in
  all: "S3 through the proxy"). The case markers are VM-reported, so a pass also needs the VM-independent
  network verification of `egress status` and squid's own log lines (from CloudWatch) for the run's
  tunnels and denials. A pass is recorded in `state/egress-verified.toml` for that image version and
  connector and bound to the connector as the network verification judged it (its Id, network
  protocol, subnet and security group, and its Version when the service answers one) and to the image
  build; any failing check of its own VM revokes the connector's records (`--vm ID` only reports).
  The check first waits (up to 60 s) for the VM to reach the proxy's port: a VM's VPC networking may
  come up after its shell. Squid's log is matched to the run on squid's own clock: a tunnel to a host
  an operator may allowlist (github.com) counts against the run only when squid logged it after the
  run's own refusal of that host. github.com is required refused unless it is on the proxy's
  effective allowlist (the `allow` list plus the extras, minus suspended hosts) as the network
  verification proved it on the proxy (the `parameters` row ok, and squid serving those values:
  active, parse ok, `applied=yes`); while it is, its case is recorded, not judged, and the record
  names it (`allowlisted`). A suspended host is judged strictly wherever it is listed; a case with no
  result fails.
- **Credentials (S7)** may enter a VM only through `egress::credential_gate`: a `vpc` VM whose live
  echo is exactly the connector, whose image version has a recorded passing check under the current DNS
  and egress rules (since S9 a pass recorded before its S3 cases does not count), and whose DNS
  verdicts (the check's and the newest `dns-path`) are `no-dns` or `platform-dns:<ip>`
  of resolvers `[egress] accept_platform_dns = "<ip>"` names (a list for several). A platform reply counts
  only as an empty NOERROR (no answer, no authority section) to a fresh name `d<nonce>.example.com`, from a
  server that also answers example.com without an address. Any other platform reply (another status, an
  authority section, a truncated reply, example.com left unanswered) is `platform-dns-answered`, an address
  is `platform-dns-resolves`, and a reply from any other server is `open-dns`: none is ever accepted.
  Records carry the DNS rule they were judged by; a `dns-path` row recorded before this rule still counts
  until the next `ai-env lab run dns-path`, so run it after upgrading. `accept_platform_dns = true` names no
  resolver and accepts nothing (doctor prints the one-line fix). Under this rule the `dnsMode = "firewall"`
  fallback cannot pass `egress check`: its DNS Firewall answers NXDOMAIN (`platform-dns-answered`). Never an
  `internet` VM.

```sh
make test-proxy                # squid on AL2023 in Docker: the allowlist, rebinding, reload, rollback (+ real systemd); no AWS
make preview-scratch [EGRESS_MODE=firewall] [NEGATIVE=…]   # read-only Pulumi preview + the plan check and its negatives
                               #   (this shell's own credentials, an agent's account)
make deploy                    # (the stack's passphrase: one Touch ID unless set; then the deployer: one paste) plan check +
                               #   replacement guard, pulumi up, connector-wait, proxy reload, egress status (its preview runs
                               #   --non-interactive: it unseals the sealed passphrase, and refuses without one: Identities)
make infra-status WRITE=1      # (ops: one Touch ID) adds egress_connector_arn and proxy_private_ip to bridge.toml [aws]
make s5-smoke                  # three `vm smoke --egress vpc --json` passes (the runtime key's Touch ID each); the echo must be
                               #   exactly the connector
make test-egress               # (deployer: one paste; the VMs' Touch IDs) the live egress tests (direct closed, allowlist,
                               #   extra + removal, after resume); a skipped proof fails it
make connector-probe CONFIRM=create-probe-connector   # (deployer: one paste; the probe VM's Touch ID) a throw-away connector:
                               #   RunMicrovm while PENDING, the activation time (~4.5 min), deleted on every path
ai-env egress check            # (the ops key's Touch ID, then the runtime key's for its VM; under ai-env as deployer only the
                               #   VM's) the recorded proof the credential gate needs (re-run after every new image version;
                               #   --if-needed: no VM when the version new VMs run has it)
make egress-logs [FOLLOW=1]    # (ops: one Touch ID) squid's access log (hosts only, never a path)
make proxy-stop                # (ops: one Touch ID) when idle: stops the proxy (no vpc VM has egress then); proxy-start brings it back
```

`ai-env doctor` shows `[NO ]` for the egress row while `[egress] require = true` (the default) and no
connector is configured; a stopped proxy is `[-  ]`, never `[NO ]`. Its DNS row says whether the newest
`dns-path` verdict is accepted, and shows the exact `accept_platform_dns = "<ip>"` line to write when the
value names no resolver. The proxy row, like every row that asks AWS, needs an identity: under
`ai-env as ops -- ai-env doctor` it is checked, otherwise it reads `not checked (no operator identity: …)`.

### Agent transport (stage S6)

`ai-env vm exec ID -- CMD ARGS…` runs a command in a VM `vm run` started, as the agent (uid 1000), over
the shim's `/agent` WebSocket through the MicroVM endpoint (`wss://<endpoint>/agent`, TLS 1.3, a
60-minute `Port(8080)` token). stdin, stdout and stderr cross as raw byte chunks of at most 64 KiB (text,
or base64 when not UTF-8): no lines on the wire, so binary output and a 20 MiB line arrive byte-exact.
The exit status is the command's own (128 + N for a signal); ai-env's own failures keep 7/8/9 with an
`ai-env:` line, the only way to tell them from a remote 7, 8 or 9 (from S7 a credentialed `claude` whose
token Anthropic refuses ends with 5 and such a line too: Credentials).

- **Sessions outlive sockets.** The VM numbers every stdout chunk and keeps it until the Mac acks it
  (an 8 MiB credit window: a reader that stops reading pauses the command, nothing is dropped); stderr
  keeps the newest 2 MiB (drops are counted); stdin is acked by the VM and resent after a reconnect. A
  lost socket is redialed with backoff (1–60 s) while the command keeps running for its detach grace
  (60 s, `--detach-grace S`; frozen while the VM is suspended); the newest client wins (`vm attach ID
  --spawn UUID`, the earlier client exits 8). A command never runs twice: spawn ids are single-use on a
  VM, so if the connection was lost before the VM confirmed the start and the VM has since let the
  command go (its grace ran out), `vm exec` exits 8 with the `vm attach` hint instead of starting it
  again. `[transport]` in bridge.toml: `rotation = "proactive"` (a
  second socket 10 min before the token expires) or `"lazy"`; `keepalive = "http"` (a `GET /health`
  every max-idle/3 keeps a running command's VM from idling into suspend) or `"frames"`;
  `suspend_wait_s` (after the VM was suspended under a client, how long it waits for someone to resume
  it — it never resumes one itself — before exit 8 naming `vm resume` and `vm attach`; since S10 a
  Cursor chat that parks waits for its next message instead, which resumes the VM: stage S10).
- **The endpoint's answers.** 401/403: one re-mint, then exit 7. 429: wait the longer of `Retry-After`
  and the backoff step (exponential when no `Retry-After` comes), never re-mint, audited `endpoint_429`.
  502: GetMicrovm decides (gone or terminating: exit 8; suspended: resume, then reattach). The shim's 503
  `not_run` (before `/run` returned) is retried for 30 s. A refused `hello` is exit 8 (`bad_token`: a
  stale row; `no_commitment`: a fail-closed `/run`). Reconnecting stops after 300 s without a lasting
  connection: exit 7 when the endpoint was still throttling, else exit 8 (`no lasting /agent connection`).
- **Signals.** Ctrl-C sends INT to the command's process group (a second within 3 s sends KILL); the
  command's own status follows. SIGTERM or SIGHUP sends TERM and waits at most 2 s for the command to
  exit, else the attachment ends for good (the VM sends TERM 0.8 s later and KILL at 1.2 s); `vm exec` exits
  143 either way. A closed stdout (EPIPE) ends it at once and exits 0. While the connection is down
  (`ai-env: lost the connection …`) nothing reaches the VM: Ctrl-C is queued and says so, and a second
  within 3 s gives up (exit 130); SIGTERM, SIGHUP or a closed stdout wait at most 10 s for the
  connection (another signal: not at all). Once it is back TERM goes out first: after SIGTERM or
  SIGHUP the command gets its 2 s before `detach final`, after a closed stdout `detach final` follows
  at once. A stop that never
  reached the VM says so: the command runs until its detach grace ends it, and
  `ai-env vm attach ID --spawn UUID` (then Ctrl-C) stops it sooner. Before the command has started
  (the endpoint throttling, the shim not up yet) Ctrl-C, SIGTERM or SIGHUP give up instead (exit 130 or
  143): no `spawn` is sent after that, a command whose `spawn` was already on its way gets the signal
  and then `detach final` as it starts, and `vm attach` leaves the spawn as it was. A signal ignored
  when ai-env started (`nohup`, a script's background job) stays ignored. `vm attach` reads stdin only
  from a terminal (Ctrl-D closes the command's stdin for good); otherwise the command's stdin is left
  as it is. On a terminal, stderr names the spawn's id and pid (for `vm attach`). No PTY: `vm shell`
  stays the interactive path.
- **What a command runs as.** uid/gid 1000 in its own session and process group, `NO_NEW_PRIVS` (no
  setuid binary or file capability changes its uid), a cleared environment (`HOME=/Users/mike`, `PATH`,
  `CLAUDE_CONFIG_DIR`, `DISABLE_AUTOUPDATER=1`, then `--env K=V`: never `AWS_*`, `CLAUDECODE`,
  `NODE_OPTIONS` or a TOKEN/KEY/SECRET/PASSWORD name; `vpc` rows also get the proxy variables), the
  working directory created and entered as the agent (`--cwd`, default HOME: no root filesystem
  operation ever touches an agent-writable path), fds 0–2 only. When the command's leader exits, its
  group gets TERM, then KILL 1 s later; once no command is left, any agent process still alive (a
  `setsid` escaper) is killed. `vm exec` and `vm attach` are refused (exit 9) on `--shell` VMs (the
  session itself refuses such a VM, whoever asks) until the platform shell's in-VM listener is shown
  unreachable from the agent.
- **The peer guard.** The platform POSTs its hooks from 127.0.0.1 inside the VM, so an address cannot
  tell it from the agent; socket ownership can. Under `--hook-source peer` (the image default) a runtime
  hook (`run`, `resume`, `suspend`, `terminate`) from a local client is admitted only when the client's
  own row in `/proc/net/tcp` (or `tcp6`) is found, live (inode ≠ 0: a client that closed before the
  lookup shows uid 0 and inode 0) and not owned by the agent uid; anything else is 403 `forbidden_peer`.
  `--agent-guard on` (the default as root on Linux) does the same on 8080 and 9418. No capability is
  needed: the image still runs with `additionalOsCapabilities: []`. `/validate` tests the guard on the
  build VM before an image can become ACTIVE (V6: the platform's own `/validate` socket is admitted, and
  `curl` as the agent POSTing `/resume` to 127.0.0.1 and to the VM's own IPv4 gets 403 — only to
  127.0.0.1, with a note, on a VM with no other IPv4; it fails when the hooks guard is off). Once
  `/run` was accepted `/validate` answers 409 without checking anything (the platform validates only
  build VMs; an agent could otherwise steer its root reads through links in its home). Every hook and
  guard line logs `peer_uid`, `ino`, `st` and the decision.
- **Side channels.** 8080 serves `/health` and `/agent` to anyone with an endpoint token; every other
  path, and every path of 9418, needs `Authorization: Bearer <session token>` (the token whose
  commitment rode `/run`). `vm health ID --detail` shows `/health/detail`: the guard's mode and
  refusals, the last admitted and the last refused peer of each hook, the sockets, the spawns, the
  listeners (one row each) and the last clock report (`--json` prints `{backend, id, detail}`, as
  `vm health --json` puts `/health` under `health`).
- **Probes.** `ai-env lab run e0|e1|e5|frames|reattach|clock-after-resume|in-vm-firewall` measure the
  live endpoint and VM: the upgrade through the proxy (`101 HTTP/1.1 403 403 403`), a socket held past its
  token's expiry, which traffic keeps a VM from idling, byte-exact frames and MB/s, a reattach without
  loss, the guest clock after a 15-minute suspension, and whether the agent reaches anything privileged
  in the VM (`guarded`, `exposed:<port>`, or `gap:<checks>` when a check could not run; IMDS, the
  setuid inventory and the platform shell's listener in the note). Ctrl-C during `lab run` still
  terminates every VM the probe started, then exits 3 (from S7 SIGTERM and SIGHUP do the same, then
  exit 143).

```sh
make test-docker               # + the agent in Docker: uid 1000, NO_NEW_PRIVS, groups, the sweep, the peer guard, /validate V6, and the real `vm exec` on the built image through the fake endpoint
make s6-smoke                  # three `vm smoke --egress vpc --exec --max-duration 900 --json` passes: backend sdk, egress_ok, exec_ok (claude --version, id -u = 1000, 401 through the proxy, 6 proxy variables)
make test-aws [SLOW=1]         # + live_agent_*; SLOW=1 adds the 65-minute rotation hold
ai-env vm exec ID -- claude --version
```

Debug builds also honour `AI_ENV_BRIDGE_LAB_AGENT_ADDR=127.0.0.1:<port>` together with the fake API:
`/agent` is then dialed in plain `ws://` at that loopback address (the tests' fake endpoint). Without the
fake API, or for any other address, it is refused; release builds compile it out.

### Credentials (stage S7)

`ai-env creds setup-token` seals a Claude setup-token (what `claude setup-token` prints after a browser
login: an inference-only OAuth token, valid for a year) as the active Claude account's (see Claude
accounts below; `default` when there is none yet), an ai-env container sealed to `[creds].key` like the
runtime key, and installs it as `credentials/setup-token.env`. It asks for the token hidden on the terminal
(`--stdin` takes exactly one line from a pipe and refuses a terminal; `--from-env` reads
`CLAUDE_CODE_OAUTH_TOKEN`); an API key (`sk-ant-api…`) is refused. What is recorded about the token, in
the container's metadata line and the audit row, is its kind prefix (`sk-ant-oat01-`), its length and
when it was sealed, never more. Clear the terminal's scrollback and the clipboard afterwards (after
`--stdin` also any file or shell history line that held it; after `--from-env`, unset the variable
instead): the command reminds you.

- **Claude accounts.** Each sealed token is a Claude account's: `credentials/accounts/<name>.env`
  (a name is 1-32 of `a-z 0-9 _ -`). One account is the active one: its token and its combined.env
  (below) are installed by byte copy as `credentials/setup-token.env` and `combined.env`, the files
  every remote chat, move and credentialed command reads, so seal ids, refusals and the VMs' caches
  work as before. `ai-env creds account add NAME` seals another (log in to claude.ai as that account
  before `claude setup-token`; one Touch ID, for its combined.env); `--use`, or a first account, makes
  it the active one. `ai-env creds account use NAME` makes another one active with no Touch ID, and a
  token Anthropic refused is never made active (exit 5). A running claude keeps the token it was
  given until its next start: `use` names each live remote chat still on another account, which
  `ai-env session migrate UUID` moves now (one Touch ID) or a reopen restarts; its next restart or
  move takes the new account. `creds setup-token` seals the active account anew (with accounts but
  none active it refuses, exit 9). The first `creds account` command, `creds setup-token` or `creds
  aws-set` adopts a token sealed before accounts existed as `default`, by byte copy and with no Touch
  ID. `ai-env creds account list` shows them (no Touch ID), `ai-env creds account forget NAME --yes`
  deletes one, and `creds status`, doctor, the audit rows (`creds_account_use` among them) and the
  VMs that may hold a token name the account. `state/accounts.toml` keeps the accounts' seal ids and
  what was seen of their usage; one that cannot be read never stops a chat or a credentialed command
  (names read `unknown`, `creds status` and doctor warn), and `creds account` never writes over it:
  remove it, and `creds account list` rebuilds it from the files. `ai-env vm exec ID --credential-file
  ~/.config/ai-env/bridge/credentials/accounts/NAME.env -- …` runs one command as another account
  without switching.
- **Names and notes.** A name is a short label you choose (`work`, `spare`), never the account's
  email: a setup-token cannot read its profile, and names reach file names, the audit, the census and
  Cursor's notes. `ai-env creds account rename OLD NEW` renames one with no Touch ID: its files, row,
  usage, note and active mark move, its sealed bytes do not (so its seal, the installed copies,
  refusals and the VMs' caches are untouched; census rows already written keep the old name).
  `ai-env creds account note NAME TEXT` (or `add NAME --note TEXT`) keeps a note with it, free text of
  1-120 characters that must never hold a credential (one that looks like a token or key is refused);
  `note NAME` alone clears it. Only `state/accounts.toml` keeps the text, and only `creds account list`
  and `creds status` show it (`work (active) [mk's Max seat]`): the audit row
  `creds_account_note` says only that it was set or cleared.
- **Usage and the live check.** A setup-token cannot read its account's limits, so ai-env learns an
  account's usage from the turns it carries, and `ai-env creds account check [NAME…]` measures it: one
  tiny turn per account (`--model haiku` by default) on this Mac's claude (Cursor's bundled one, else
  PATH's), one Touch ID each, then its 5-hour and weekly use with their resets (`work (active): 5h 23%
  (resets 14:00Z), 7d 81% (resets Thu 10:00Z)`), or the limit it hit (`spare: limited: weekly, "resets
  10am (UTC)"`). The token goes on fd 3 (in the environment under `[creds] deliver = "env"`) to a claude
  with an empty environment and a fresh HOME, never in its argv; a refusal is recorded as `vm exec`
  records one, and a seal already refused costs no Touch ID. It exits 3 on a dismissed dialog, 5 at the
  Touch ID deadline or when an account was refused, 130 or 143 when stopped, 1 when a run failed;
  `--json` adds each run's `rate_limit_event` and result lines, scrubbed.
- **One Touch ID per credentialed command.** In container mode the runtime key is a Touch ID of its
  own. `creds setup-token` and `creds aws-set` therefore also write `credentials/combined.env`: both
  credentials in one container, recording the hashes of the two files it was built from, so `vm exec
  --with-credential` unseals both with one prompt. When either source changes, `combined.env` is out of
  date and is not used: the token costs a second prompt until `creds setup-token` (or `make
  runtime-key`) rebuilds it. A rebuild removes the old one before its prompt, so one that cannot finish
  (that prompt dismissed or interrupted) never leaves a copy of a replaced credential behind; a
  dismissed one says so. One whose source another command sealed anew (or forgot) while it waited
  builds none from what that replaced, and says so. The seal itself still succeeds (`creds setup-token`
  writes its audit row and its `setup-token-prefix` probe row before the rebuild). `--credential-file`
  always costs two Touch IDs: the runtime key, then the file's own container. `creds status` shows
  which case holds, without a prompt. Each Claude account has its own,
  `credentials/accounts/<name>.combined.env`, judged against its own token and installed as
  `combined.env` only beside it: `make runtime-key` rebuilds every account's, one Touch ID each, the
  active one first, and an account whose rebuild failed costs two Touch IDs once it is made active,
  until the next one.
- **Delivery.** `ai-env vm exec ID --with-credential -- claude -p '…'` runs the credential gate before
  the token is sent. Without a Touch ID: a vpc VM whose egress echo gate passed, not a `--shell` VM, a
  shim that can hold a credential (once its `/health` was read), a passing `egress check` recorded for
  its image version within 7 days, an accepted dns-path verdict. Then the runtime key's Touch ID, and
  with it the live checks: the egress echo, an ingress of exactly `HTTP_INGRESS`, the connector's facts
  and the image build. With a current `combined.env` that one Touch ID has unsealed the token as well,
  before any AWS call: it waits in ai-env's memory for the gate and is dropped unsent when the gate
  refuses. Without one, the token is unsealed only once the gate passed, and only when the VM does not
  hold it already. It goes in its own `credential` frame to the VM's shim, which keeps one copy in
  memory and hands it to the command on fd 3 (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3`; claude reads
  it once), or, under `[creds] deliver = "env"`, in its environment (see Environment delivery). A later
  credentialed command on the same VM finds that copy: the token is not sent again, and without a
  current `combined.env` not even unsealed. `vm warm WORKSPACE` delivers ahead of time (starting the
  workspace's VM with vpc egress if it has none), so a later command needs no Touch ID for the token.
  `vm warm`, `vm smoke --with-credential` and the credential probes (`lab run fd-delivery` and
  `init-budget`) choose their VM after the Touch ID: before it they check the gate's local half on the
  row a run would make, for the image version the configuration names (for `active`, the one
  `state/infra.toml` records), then the chosen VM's own row; with a current `combined.env` the token
  waits in memory while that VM starts (and, in the smoke, through its exec steps).
  `--credential-file PATH` gives one command the token sealed in another container; it is never kept
  on the VM.
- **How long the VM holds it.** The shim's copy is dropped on `/suspend` (before the platform takes its
  snapshot), on `/resume` as a backstop, on `/terminate` and at shutdown. A command already running keeps
  its own copy, and so does any snapshot taken while it ran: until the VM is TERMINATED it may hold the
  token, whatever `has_credentials` says. `creds status` and `creds forget` list the VMs that may hold
  it: each VM is recorded before the token leaves the Mac for it, as is any VM later seen holding it. A
  VM registry row they cannot read is listed too, as one whose VM may hold it (`[!! ]` in
  `creds status`, `holders_unreadable` in its `--json`), so the list never reads none while one exists.
  `vm health ID --detail` shows the shim's copy (name, seal and time, never the value) and how many
  running commands were handed a secret; a command whose leader exited while a process of its group
  runs on still counts, and reads `group` under ALIVE.
- **Copies that are not zeroized.** ai-env's own copies of the token (the unsealed plaintext, the
  `credential` frame's value, the shim's cache) are zeroized when dropped. Some are freed without that,
  as the design accepts: the frame's JSON text, the WebSocket and TLS buffers it passes through
  (tungstenite, rustls), serde's scratch space and the kernel's pages of the fd-3 pipe (with environment
  delivery also the environment the shim, or the wrapper, builds for the child). They stay in freed
  memory of the Mac process and of the shim until reused: one more reason a snapshot taken after a
  delivery may hold the token until the VM is TERMINATED.
- **Environment delivery.** `[creds] deliver = "env"` both allows `--deliver env` and makes it the
  default: `vm exec --with-credential` or `--credential-file` without `--deliver`,
  `vm smoke --with-credential` and the wrapper's `local-scratch` child then get the token in their
  environment, readable by everything they start; `--deliver fd` still puts it on fd 3. Without that
  setting (the default is `deliver = "fd"`) fd delivery is the default and `--deliver env` is refused
  (exit 9).
- **A rejected token.** `vm exec --with-credential` watches only a command whose program (the first word
  after `--`, by its basename) is `claude` itself: one started through `sh -c`, `env` or another wrapper
  is not watched, its status passes through and nothing is recorded. Two signs count as Anthropic
  refusing the token (HTTP 401). With `--output-format stream-json --verbose` claude prints its own
  retries: at the third `api_retry` with HTTP 401 since its last answer (a model reply or an answered
  turn starts the count again; a reply over 64 KiB is read by its first 512 bytes), `vm exec` stops
  the command (TERM to its group, KILL 3 s later, then `detach final`), then checks for at most 5 s
  that it and its process group are gone, naming `ai-env vm terminate` when it cannot see that. In any
  output format, claude's own 401 at its end, followed by exit 1, counts too: an error result whose
  `api_error_status` is 401, whatever its wording, or a line (or an error result's text) that starts
  with claude's 401 message (`Failed to authenticate. API Error: 401`, as claude 2.1.296 words it in
  S7's B7; `API Error: 401`, `Invalid API key` and `OAuth token has expired` are kept from before B7,
  unmeasured, for plain text without that prefix). That command has ended by itself, and nothing is
  stopped. On claude 2.1.296 a `claude -p` gives up after two retries, so this second sign is the one
  that ends it, in stream-json as in json. With `--output-format json --verbose` claude prints the
  run's messages as one JSON array on one line (S7's B16, on claude 2.1.296): each is read as a line of
  its own would be, if the array is at most 64 KiB. Either way
  `vm exec` exits 5 with an `ai-env:` line saying what it saw, written last on stderr (a later
  SIGTERM, SIGHUP or Ctrl-C keeps the 5; a SIGTERM or SIGHUP during the stop, or any of the three
  during the check, leaves the last output at most 3 s, as a stop does; a stderr nobody reads gets no
  line), audits `credential_rejected`, and never starts the command again; `vm smoke --with-credential`
  records a refused `claude -p` the same way. The rejection is recorded against the sealed container:
  credentialed commands then refuse at once (exit 5, no Touch ID) until a new token is sealed for that
  account, or `creds account use` makes another one active (a refused account is never made active).
  With accounts, the refusal's line names the account and its fix: `claude setup-token` logged in to
  claude.ai as that account, then `ai-env creds account add NAME`. Not `creds setup-token`, which
  seals the active account anew: after a `creds account use` that is another account, whose seal it
  would replace with this one's token. With no account at all, `creds setup-token` is the fix (a chat
  that ran as a refused account says the same in its last line). That record is `state/creds.toml`:
  one that cannot be read refuses them too (exit 5, naming it, since which tokens were refused is
  then unknown), the wrapper's `local-scratch` child then runs
  logged out, and `creds status` and doctor show it as a warning. A refused `--credential-file`
  container with a seal of its own blocks only itself; the sealed setup-token is not affected. A byte
  copy of `setup-token.env` has the sealed token's seal, so its refusal is the sealed token's.
- **Forgetting.** `creds forget` lists, then with `--yes` deletes, `setup-token.env`, `combined.env`,
  every Claude account (`credentials/accounts/` and `state/accounts.toml`) and their backups; `aws.env`
  stays. `creds account forget NAME` deletes one account the same way (its files, its backups, and the
  installed copies when it is the active one, which leaves none active). Neither can revoke a token,
  which Anthropic honours until it is revoked. To retire one: revoke it in the claude.ai account that
  created it, under Settings, then Claude Code (https://claude.ai/settings/claude-code; Anthropic's
  Help Center article 10310342); check that it is refused (a credentialed command such as
  `ai-env vm exec ID --with-credential -- claude -p 'Reply OK'` exits 5 with the
  `ai-env: Anthropic refused the delivered setup-token` line, or `make test-claude` fails on a 401);
  then `ai-env creds forget --yes` (or `ai-env creds account forget NAME --yes` for one account), and
  terminate the VMs `ai-env creds status` lists, which may hold a copy until they are TERMINATED.
- **Touch ID and signals.** Every Touch ID of a credentialed command (the runtime key's too) shows a
  countdown and has a deadline, `[creds].unseal_timeout_s` (default 60, 10–600). A dismissed dialog is 3;
  no answer in time is 5 (`vm exec` names `vm warm` for the token's own prompt, which a warm VM spares);
  Ctrl-C while waiting closes the dialog (130), SIGTERM or SIGHUP too (143). From the first Touch ID on, a
  credentialed `vm exec` (until its command starts) or `vm warm` (to its end) stops at once on any of
  the three, with an `ai-env:` line. `vm exec` then sends nothing. `vm warm` gives its delivery up where
  it stands: the VM is recorded as one that may hold the token before the token leaves, so the line
  says whether it may, as `creds status` does. A `vm warm` stopped while its RunMicrovm is in flight
  first looks for the VM that call may have started, saying so and for how long (up to 60 s; a second
  stop gives the search up and keeps the pending row for `ai-env vm gc`), then names it. Once past
  their first Touch ID, `vm smoke` and the live `lab run` probes end the VMs they started and exit 3 on
  Ctrl-C, 143 on SIGTERM or SIGHUP; the Mac probes `touchid-gui` and `oauth-t1` keep the signals'
  default actions. A signal ignored when ai-env started stays ignored.
- **Exit codes.** A gate refusal is 9, naming its condition and what to run. So is a gate pass older
  than 90 s by the time the VM was ready: nothing was sent (on a re-send, nothing more); run the command
  again. A VM whose shim cannot hold a credential (an image before S7) is 7, and never costs the token a
  Touch ID of its own. No sealed token, or a rejected one, is 5; so is a token sealed anew while the
  command ran (nothing is sent; one sealed anew before its own unseal is refused before its Touch ID),
  and a VM that no longer holds the token when none is in hand (its line says to run the command
  again). A shim whose credential cache stays closed after the VM runs again
  is 8. An unseal only checks that `[creds].key` exists (else 4): a key that did not seal the file
  fails inside age (1), and a credentials file that is not an ai-env container is 5, not 6; `creds status`
  names the key that opens each file. `lab run fd-delivery` and `init-budget` keep the exit code of a
  credential step that fails, as `vm exec` would (a missing key stays 4).

```sh
ai-env creds setup-token        # paste what `claude setup-token` printed (hidden); rebuilds combined.env with one Touch ID
ai-env creds status             # what is sealed, combined.env against its sources, the credential gate's local preconditions,
                                #   a recorded refusal, the Claude accounts, the VMs that may hold the token: no Touch ID
ai-env creds account list       # the Claude accounts, the active one marked: no Touch ID
ai-env creds account add work   # paste what `claude setup-token` printed, logged in as that account (hidden); one Touch ID
ai-env creds account use work   # new chats, moves and credentialed commands take it (no Touch ID); names the live chats still on another
ai-env creds account check      # one turn per account on this Mac's claude, a Touch ID each: 5-hour and weekly usage and their resets
ai-env vm exec ID --with-credential -- claude -p 'Reply with exactly OK' --output-format json
ai-env vm warm ~/work/project   # deliver ahead of time
make test-claude                # T7.2 on this Mac: the token drives the real claude (real model requests)
make s7-smoke                   # three `vm smoke --egress vpc --exec --with-credential` passes: exec_ok and cred_ok true
make test-aws CRED=1            # + live_credential_*: two answers with one delivery, a garbage token refused (exit 5), no internet VM;
                                #   Touch IDs: the test process's, one per answer, two for the garbage token's --credential-file (the runtime key, the file)
```

Debug builds also honour `AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS=<n>` here (the wrapper's knob of that
name): every unseal a credentialed `vm` or `lab` command makes (the runtime key alone or with the
token in `combined.env`, the setup-token, a `--credential-file`) then has n ms in place of
`[creds].unseal_timeout_s`, so a test reaches the deadline in a second or two. Like the S4 knobs it
is announced on stderr and marks the `--json` records (`"backend":"sdk+knobs"` against the real
service, whose smoke budgets are then not judged); the Mac probes ignore it, the live Makefile
targets drop it, and release builds compile it out.

### Cursor in a MicroVM (stage S8)

**What happens.** In remote mode a Cursor chat runs in a MicroVM: its turns, tool calls, permission
prompts and interrupts happen in the workspace's VM, as the agent (uid 1000), behind the egress
allowlist, logged in with the sealed setup-token (S7). Cursor still starts `ai-env-claude` from
`claudeCode.claudeProcessWrapper`. For a stream-json session whose working directory is under
`[workspaces].roots` (a chat and Cursor's config probe alike, and any other session Cursor starts
there: the sign-in it runs when you log in with no chat open, and the prompt-suggestion
queries it runs only with `CLAUDE_PROACTIVE_SUGGESTIONS=true` in its own environment), the wrapper
picks the workspace's VM, seeds the workspace into it at the identical absolute path
(the image's agent is `/Users/mike`, as on the Mac), starts claude there and relays its stream (since
S9 without `--session-mirror`: the transcript stays in the VM and in S3, and the Mac keeps a view of it,
see stage S9); the `initialize` answer carries the wrapper's own pid. Everything else
(`auth status`, `mcp add` and every other subcommand, `--version`, a session outside the roots) execs
the bundled claude on the Mac, as in passthrough. Under the roots a remote session fails closed: an exit
code and one `ai-env-claude:` line, never a silent run on the Mac. That holds even when bridge.toml does
not load: the wrapper still reads its mode and roots as plain TOML, and a session under them exits 1
with the error's first line (roots it cannot read, a misspelt `roots` or `path` key included, hold every
session; since S9 (F1) so do a `roots` or `path` key outside any table and a table one typo from
`[workspaces]` or `[[workspace]]`, such as `[worksapces]`, while an unknown `[wrapper]` key, a table one
typo from `[wrapper]` (`[wraper]`) or a `mode` key outside any table leave the mode unreadable, which
counts as remote; a file that cannot be read or is not TOML at all fails every session unless
`AI_ENV_BRIDGE_MODE` names a mode other than `remote`; with no bridge.toml there are no roots). A
workspace has one VM: the config probe and the chats share it, and a reopened chat goes back to the VM
it ran on while that VM lives (since S10 a lost VM moves an open chat to a new one, and a VM near its
wall migrates it: stage S10).
When Cursor closes a chat the wrapper exits within 1.5 s: claude in the VM gets 1.2 s to end by itself
(it takes 0.5 to 1.1 s), then the VM's shim finishes the job (a parked chat whose VM is suspended
closes at once: stage S10).

**Install and switch on.** `make install` puts `ai-env` and `ai-env-claude` in `~/.cargo/bin` (never
point Cursor at a build under `target/`: `cargo clean` would break it). Then, from the installed
`ai-env`, `ai-env wrapper install --write --mode remote` sets Cursor's wrapper as S1 does and
`[wrapper] mode = "remote"` in bridge.toml, backing both files up first; without `--write` it prints
what it would change. The chats Cursor starts from then on run remote; a window reload moves the
chats already open (it restarts them). `ai-env wrapper status` shows the result. `[workspaces].roots`
(and each `[[workspace]] path`) decides which workspaces go remote: keep it narrow while you try it
out. `ai-env doctor` shows the mode,
whether the image new VMs run serves the workspace routes (`workspace_v1`: an image older than S8 needs
`make deploy`) and the `[seed]` caps, and since S9 each workspace's pre-push hook (stage S9) and a
`[!! ]` for each open Cursor window still on another extension than the one installed
(`a Cursor window runs extension V (host pid N, since T); W is installed  <- reload that window`, from
the census: each live extension host's newest row); `ai-env creds status` shows the sealed setup-token
and whether `combined.env` is current.

```sh doc-test
ai-env wrapper install --write --mode remote   # Cursor's wrapper setting and [wrapper] mode = "remote" (backups first)
ai-env wrapper status                          # the setting, the effective mode and roots, the extension Cursor last ran
ai-env doctor                                  # the mode, the image's workspace_v1, the [seed] caps
ai-env creds status                            # the sealed setup-token and combined.env, without a Touch ID
```

**The kill switch.** `AI_ENV_BRIDGE_LOCAL=1` in `claudeCode.environmentVariables` (Cursor's user
settings: a list of name and value pairs) makes the wrapper exec the bundled claude before it reads
anything: plain Cursor on this Mac, no AWS call, no census, no Touch ID. Since S9 it reads one thing
first, the first 4 KiB of the chat file a `--resume` or `--continue` names, and refuses a remote chat's
view (exit 9; stage S9). It is the way out when remote
mode itself is broken. `AI_ENV_BRIDGE_MODE` in the same list overrides `[wrapper].mode` (`passthrough`
or `remote`), and `ai-env wrapper install --write --mode passthrough` switches remote mode off in
bridge.toml. VMs already running stay until they suspend, reach their wall or are terminated.

```json
{
  "claudeCode.environmentVariables": [
    { "name": "AI_ENV_BRIDGE_LOCAL", "value": "1" }
  ]
}
```

**No wrapper at all.** `ai-env wrapper uninstall --write` takes `claudeCode.claudeProcessWrapper` out
of Cursor's settings (backup first; `initialPermissionMode`, `environmentVariables` and bridge.toml
stay; without `--write` it shows what it would remove), and the `undo:` line it prints puts it back:
`ai-env wrapper install --write`, with `--permission-mode` when install would otherwise set
`initialPermissionMode` to another value. The chats Cursor starts after that run in the mode bridge.toml
names, unless Cursor's `environmentVariables` override it (uninstall says so). Cursor reads the
setting each time it starts a process and never restarts a running chat for a settings change, so a
chat keeps the binary it started with. That keeps one chat on this Mac while remote mode serves the
others: take the setting out before a window reload (a restored chat starts its process as soon as it
is restored, before any message), let that chat answer once, then put the setting back without
reloading, and start the chats meant for a MicroVM with New Conversation (the blank chat Cursor
preloaded at the reload is local too). Taking the setting out or putting it back makes every open
Claude view start `auth status --json` and a config probe about 1.5 s later: once the setting is back,
each config probe under the roots asks for a Touch ID, and `auth status`, which runs on this Mac, may
start the prewarm (one more). A local chat goes remote whenever Cursor starts a process for it again:
a window reload, a Cursor or extension-host restart, Reload Claude, closing and reopening its tab,
opening it in a second window, a rewind or fork (a new session), or its process ending (the next
action that needs one starts it again). Since S9 a remote chat's file on this Mac is only its view, and
a reload with the setting out resumes every open chat on this Mac, past the wrapper: close the remote
chats' tabs first (`wrapper uninstall` warns while such views exist; stage S9).
`ai-env wrapper status` shows where the chats Cursor starts next will run: the setting and the
`ai-env-claude` it names, the kill switch and `AI_ENV_BRIDGE_MODE` in Cursor's list, the effective
mode, the roots, whether bridge.toml passes the checks a remote session runs at its start, the
extension version Cursor last ran (from the census, which only the wrapper writes: after a change to
Cursor's settings.json it names none until Cursor has started a process through the wrapper), and since
S9 the one each open Cursor window runs (a window keeps the extension it loaded until it is reloaded).
It cannot see a chat that is already running.

```sh doc-test
ai-env wrapper install --write --mode passthrough   # every chat on this Mac again
ai-env wrapper uninstall --write                    # no wrapper at all: Cursor runs its bundled claude (backup first)
```

**A Touch ID per session (D1).** Every remote wrapper process unseals the runtime key itself: one Touch
ID each for the chat and the prewarm below, and for any other session Cursor starts under the roots:
the sign-in, prompt-suggestion queries when enabled, and Cursor's config probe, which it starts only
when a Claude view asks for its config and no chat claims the request within 0.5 s: after the wrapper
setting is set or cleared, a sign-in or sign-out, or a chat that ended before answering `initialize`.
A new tab's chat launches within tens of milliseconds and answers the request itself (a tab Cursor
restores with a window may launch later, and its launch then stops the probe that started meanwhile),
so a window's first Claude tab asks two (the prewarm's, then its chat's) when the workspace has no VM
to reuse, and every later tab one (a prewarm that stages a new version aside: stage S11). With a current
`combined.env` that one prompt also opens the setup-token for a VM that does not hold it yet (without
one, that is a second prompt). Nothing keeps a key between processes
(S15's daemon is the later fix), so a Cursor reload costs two to four prompts, shown one at a time. The
countdown goes to the wrapper's stderr, and the dialog must be answered within Cursor's 60 s
`initialize` window less 11 s. A dismissed dialog exits 3, with the line
`Touch ID was cancelled: nothing was started; reopen the chat to try again`; no answer in time exits 5,
with the line
`no Touch ID within N s (Cursor's 60 s window): nothing was started; ai-env vm warm prepares the VM ahead`.
Since S10 an open chat that moves to a new VM asks one more, for the setup token alone, in a dialog of
`[creds].unseal_timeout_s` within the move's 180 s (what a dismissal does then: stage S10).
With several Claude accounts each of these prompts opens the active account's token, as
`credentials/setup-token.env` holds it at that moment (`ai-env creds account use NAME` switches it, with
no Touch ID): a new chat, and the next move of an open one, take the switch; a running claude keeps
the account it started with.
When Cursor opens a window it runs `auth status --json`; under the roots the wrapper then starts
`ai-env vm warm WORKSPACE --prewarm` detached, so the VM is running and seeded before the first chat.
`[vm] prewarm_on_auth_status` is `"auto"` (the default: only when the workspace has no VM to reuse),
`"always"` or `"never"`; the prewarm needs the `touchid-gui` probe's `prompted` (a detached process can
show the dialog) and costs a Touch ID of its own. Every setting skips a working directory in no git work
tree (`prewarm:skipped(not_git)` in the census), a pinned VM (`AI_ENV_BRIDGE_VM`: `pinned`) and
`[vm] reuse_per_workspace = false` (`reuse_off`), and starts none within 120 s of the last one (`recent`);
a prewarm refused at its prechecks (a workspace a session would refuse) logs `no prewarm: …` in
`logs/ai-env.log`. Fewer prompts: `prewarm_on_auth_status = "never"`, or
`[aws] credentials = "profile:NAME"`, which reads the runtime key from an AWS profile without a prompt
(weaker custody: the key sits in a plain file); a session on a VM that holds the token already then asks
for none. `vm warm` by hand takes the VM's start and the seed out of Cursor's window.

```sh doc-test
ai-env vm warm WORKSPACE   # start or reuse the workspace's VM, seed it, deliver the token (one Touch ID)
```

**Seeding (D2, D3, D7).** Before claude starts, the wrapper seeds the workspace into the VM (the
snapshot is taken beside the Touch ID); `ai-env box seed` and `vm warm` do the same from a terminal. A
seed carries HEAD's commit and tree, on its branch (or detached), and one WIP commit of the uncommitted
changes: tracked edits, staged changes and the untracked files git does not ignore, which the VM checks
out uncommitted, as on the Mac. It never carries the history (the VM's clone is shallow at the seeded
commit: `git log` there starts at it), other branches, tags, the stash, ignored files, submodules or LFS
objects, and the VM's clone has no `origin`. The snapshot is built in a scratch repository under
`state/tmp/`: your index, working tree, stash, refs and objects are never touched. Before a byte leaves
the Mac, every object of the seed (commit messages included) goes through the tripwires; every
`.claude/settings.json` and `.claude/settings.local.json` the VM would check out goes through the repo
settings rules (D8: a `defaultMode` other than `default` or `plan`, `bypassPermissions`, a broad allow
such as `Bash(*)`, a bare `Write`, `Edit` or `WebFetch`, any `mcp__` entry, `hooks`, `apiKeyHelper`, a
command `statusLine`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, MCP auto-approval,
`additionalDirectories`); and a `.env`, `.env.*` or `*.env` file the WIP adds must be an ai-env
container (`AI_ENV=1`; `*.example`, `*.sample`, `*.template` and `*.dist` pass). A finding is exit 9
naming where it is (the ref and path, or the commit), the rule and the JSON key, never the value.
`[[workspace]] trust_repo_settings = true` turns the settings rules off for that workspace, never the
tripwires. `ai-env box seed --dry-run` shows what a first seed would carry (HEAD's commit and tree and
the WIP, no history), or the findings that refuse it (at most 20 lines: past 20 findings, the first 19
and how many more; identical files are named at one of their paths), with no AWS call and no Touch ID.
It reads no history: the commits an update carries (those since the VM's seed) are scanned when
`box seed`, `vm warm` or a chat builds the update (exit 9, a file named at the commit that brought it).

A workspace that is not a git repository is refused at once, before any Touch ID (exit 9,
`not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally`); a
shallow, bare, sparse or partial clone, or a repository without a commit, is exit 1. `[seed]` caps the
WIP at 5000 untracked files and 64 MiB of new bytes, and every file a seed carries at 64 MiB
(`max_blob_mib`, at most 1024): a WIP over a cap, or an uncommitted file over `max_blob_mib`, is exit 9
naming the five largest; a committed one is a finding (`blob-too-large`, exit 9) that neither
`--no-wip` nor `trust_repo_settings` lifts: raise `max_blob_mib`, or take the file out of HEAD (a VM
seeded before the file came still meets it in the commits an update carries, which the dry run does not
show: `ai-env vm terminate ID`). What the wrapper sends inside Cursor's window is capped at 64 MiB
(`wrapper_inline_mib`; above it, seed from a terminal with `vm warm` or `box seed`, up to `max_mib`,
512 MiB).
`[[workspace]] seed_wip = false`, or `box seed --no-wip`, leaves the uncommitted changes on the Mac
(`seed_allow_dirty` is deprecated and ignored).

A VM seeded before is fast-forwarded when its checkout is clean, on the same branch, and its tip is an
ancestor of the commit seeded (your HEAD, or `--branch`'s tip).
Anything else keeps the VM's state (`seed:kept` in the census; `box seed` prints
`the VM keeps its state (dirty): ai-env box fetch shows what changed`, or `ahead`, or `diverged`), and a
VM seeded with uncommitted changes counts as dirty, so it is never fast-forwarded on its own. Then fetch
and merge what the VM did (below) and `ai-env vm terminate ID`: the next chat seeds a fresh VM.
`ai-env box seed --replace` checks out a VM anew only while it is unchanged since its seed.

```sh doc-test
ai-env box seed WORKSPACE --dry-run   # what a first seed carries, or its findings: no AWS call, no Touch ID
ai-env box seed WORKSPACE             # seed, or fast-forward, the workspace's running VM (one Touch ID)
```

**Code out.** After every turn (each `result`) the wrapper fetches in the background: the VM snapshots
its uncommitted files into a `refs/wip/*` ref, and the Mac imports the VM's branches into
`refs/remotes/box/BRANCH` and its snapshots into `refs/remotes/box/wip/*` (the newest 64,
`[seed] keep_wip_refs`). The fetched objects go through the tripwires, the settings rules and
`max_blob_mib` again, and a ref with a finding lands in `refs/remotes/box-quarantine/*` instead. Your
branches, index and working tree are never touched: review the refs with git and merge by hand, and
never push a `box/*` ref (S9's `box review` checks what a push carries, and its pre-push hook refuses
a `box/*` ref; stage S9). A failed fetch goes to the
wrapper's log and the chat carries on. `ai-env box fetch` does the same by hand, from the workspace's
VM or a chat's (by its session id), a suspended one too; a ref with a finding is exit 9. The VM also
snapshots its checkout when it is suspended, never when it is terminated (the disk goes with the VM).

```sh doc-test
ai-env box fetch WORKSPACE --wip   # the VM's commits and a snapshot of its uncommitted files (one Touch ID)
ai-env box fetch UUID --dry-run    # a chat's VM: the refs that would move, nothing fetched
```

```sh
git branch -r --list 'box/*'              # what came back
git log --oneline BRANCH..box/BRANCH      # the VM's commits on your branch
git diff BRANCH...box/BRANCH              # their changes
git merge --ff-only box/BRANCH            # take them (or cherry-pick), then push your branch as usual (S9's hook reviews it)
```

**Picker and resume.** The VM's claude writes the transcript in the VM. Since S9 it stays there and in
S3, and the Mac's `~/.claude/projects/` holds only its view (the last 10 messages) under the workspace's
project name, so Cursor's picker lists the chat as before (stage S9). Reopening it starts a session with
`--resume`: the wrapper takes the VM the chat ran on while it lives, which keeps its copy; on a new VM
(the old one terminated, or past its wall) it seeds the workspace and restores the transcript from S3
before claude starts (since S10 the seed is the old VM's last fetched work, and a reopen near the old
VM's wall moves the chat off it first: stage S10). A chat begun on this Mac goes up the first time it
reopens remote, its transcript and its subagents' files through the tripwires first (see Security): a
finding is exit 9 and none of it is sent. `ai-env session show UUID` shows a chat's VM, spawn, seeded
head and newest fetched snapshot, since S9 where its transcript is kept (`transcript_home`), where it
began (`origin`) and its view, and since S10 every VM it ran on (`vms`, with why each started).

```sh doc-test
ai-env session list        # the chats the wrapper registered, newest first
ai-env session show UUID   # one chat's row: its VM, spawn, seeded head, newest fetched snapshot
```

**Settings that last (T8.7).** A rule approved with "don't ask again" in a remote chat is written into
the VM's settings (the workspace's `.claude/settings.local.json` there), so the next VM, started from
the image, asks again. The wrapper captures the VM's settings into
`~/.config/ai-env/bridge/quarantine/UUID/settings/` when the session starts (`start.json`) and after
each code-out (`latest.json`), never during the close: a rule approved after a chat's last answer is
missed. Each capture names its VM, and the last capture of each VM the chat ran on is kept: a chat
reopened on a new VM (the old one gone) keeps the old VM's as `latest-ID.json`, so a rule approved
there stays in the diff (settings-sync lists it as `already in the image` once promoted) until
`ai-env session forget UUID` removes the captures.
`ai-env session show UUID --settings-diff` shows the rules added in any of them (and in which VM),
then each VM's other changes, per scope (allow, deny and ask rules removed, `defaultMode`, other keys
by name only, `env` values masked), and writes it to `diff.json` there. Since S9 a turn's capture equal
to its VM's newest one leaves `settings/checked.json` (when, and in which VM), so a chat that changed
nothing reads `no change since the start capture (last checked T in VM ID)`.
`ai-env wrapper settings-sync UUID --rule R` (repeatable, or `--all-safe`) shows how
the rules would go into `image/claude/settings.json` and the settings policy; `--write` makes the change
(backups first), scans the image again and rolls back unless it is clean. It never promotes a broad
allow, anything the repo settings rules refuse, or `defaultMode`. Then build and deploy the image, and
run `ai-env egress check --if-needed` (a new image version needs its check before a credential goes in):
new VMs have the rule.

```sh doc-test
ai-env session show UUID --settings-diff                              # the settings the chat changed in its VMs
ai-env wrapper settings-sync UUID --rule 'Bash(git status)' --write   # into image/claude/settings.json and the policy
```

```sh
make test-docker deploy   # the image with the rule (test-docker builds the zip and stamps it; deploy asks for the deployer's key)
```

**Not supported in a remote chat:**

- IDE tools (diagnostics, open editors, diffs, code execution): their MCP server is on the Mac's loopback;
- `@`-mentions of files that exist only in the VM (the picker lists the Mac's files);
- rewinding (file checkpoints) once the chat moved to another VM: the file history stays where it was made;
- more than one workspace folder: `--add-dir` is stripped (`[wrapper] strip_add_dir`), and only the
  folder the chat starts in is seeded;
- user-scope MCP servers: `claude mcp add` runs on the Mac and edits the Mac's `~/.claude.json` (the
  wrapper says so); the VM has the servers of a committed `.mcp.json` only;
- Chrome MCP (its command is the Mac's wrapper path), claude.ai MCP servers, artifacts, Remote Control
  (a setup-token cannot) and installing system packages;
- a workspace that is not a git repository (exit 9, above).

**Misleading, not bugs** (the extension's own hooks act on the Mac's files):

- after an edit, the diagnostics the extension reports are those of the Mac's copy, which the edit did
  not change;
- autosave saves the Mac's editor buffer only; it never reaches the VM;
- a file link in the chat opens the Mac's copy, which changes only when you merge `box/BRANCH`
  (`box fetch` moves refs, never your working tree);
- the inline diff's baseline is the Mac's file, not the VM's.

**Security:**

- the VM holds the delivered setup-token (S7) and the agent can read it there: an inference-only token,
  good for model requests and nothing else; a suspended VM's snapshot may hold it until the VM is
  TERMINATED (since S10 every parked chat's VM is such a snapshot, claude's copy in it: stage S10);
- the VM reaches the network through the allowlist only (S5: `api.anthropic.com`,
  `platform.claude.com`, `index.crates.io`, `static.crates.io`, and `egress allow` extras), and the
  wrapper sets `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (with `[egress] disable_nonessential`),
  `DISABLE_AUTOUPDATER=1`, `ENABLE_CLAUDEAI_MCP_SERVERS=false` and `CLAUDE_CODE_DISABLE_ARTIFACT=1` for
  claude there;
- of Cursor's environment only the names in `[wrapper] env_forward` and `env_extra` go to the VM; a name
  there that `vm exec --env` refuses (`AWS_*`, a TOKEN, KEY, SECRET or PASSWORD name and the like), a
  proxy variable or `CLAUDE_CODE_PROJECT_DIR_NAME` refuses the session (exit 9, the name named, never a
  value);
- the scans are tripwires, not proofs: a secret in a shape no rule knows, in a tracked or untracked
  file, goes to AWS; `box seed --dry-run` shows what a first seed would carry. A chat's transcript holds
  what its tools printed: since S9 a remote chat's stays in the VM and in S3 (the Mac never receives it
  and keeps only its masked view), and a chat begun on this Mac goes through the same tripwires, with
  its subagents' files, before it is sent: a finding is exit 9 naming `transcript:UUID.jsonl` (or the
  subagent's file), the line and the rule, and none of it is sent; go on with that chat on the Mac
  (`AI_ENV_BRIDGE_LOCAL=1`, the kill switch) or start a new one;
- a VM ref whose name looks like a credential (the scrubber would change it, or a tripwire matches it)
  never reaches your refs, logs or output: since S9 the VM's helper lists it under a stand-in, and the
  Mac keeps it out and counts it without naming it (`N VM ref(s) skipped: a name that looks like a
  credential (not shown)` in `box fetch`, `hidden` in the `codeout_fetch` row, a line in the wrapper's
  log at most every ten minutes); a ref naming no commit (a tree, a blob or a tag) is kept out too and
  counted in a line of its own (`N VM ref(s) skipped: an object that is no commit (a tree, a blob or a
  tag; not shown)`), never named;
- the VM has no `origin` and no push credential: nothing the agent writes reaches a remote before you
  merge it and push it yourself, and since S9 the pre-push hook reviews that push (stage S9).

**Cost and clean-up.** An open chat keeps its VM running, and billed, while it works. Since S10 an idle
one parks after `[vm] park_after_s` and the idle policy then suspends its VM, at most 10 minutes after
its last activity at the defaults (stage S10); with `[vm] park = false`, or on a VM of an older image,
the session's keep-alive holds off the idle policy for as long as the chat stays open, up to the VM's
wall, `[vm] max_duration_s`. When the last chat of a workspace closes, the wrapper suspends its VM
(`[vm] suspend_on_close`); otherwise the idle policy suspends it after `[vm] max_idle_s`, and a
suspended VM is terminated once its suspended time or its wall runs out.
`ai-env vm terminate --all --yes` ends every VM you started; do it at the end of a day, since a snapshot
may hold the token until then.

```sh doc-test
ai-env vm list       # the VMs, their state and the wall time left
ai-env vm gc --yes   # terminate expired VMs and clear stale rows (without --yes: the report only)
```

**Troubleshooting.** What Cursor shows, and what it means:

- `Claude Code process exited with code N. stderr: …`: the end of the wrapper's stderr, whose last
  line is `ai-env-claude: …` naming the fix. N is 1 (bridge.toml, the workspace's repository, a
  seed too large for Cursor's window, or since S9 a `state/infra.toml` that records no transcripts
  bucket, `make infra-status WRITE=1`: the line says which), 2 (`AI_ENV_BRIDGE_VM` is not a MicroVM
  id), 3 (Touch ID dismissed, a move's too), 4 or 6 (the keystore key, or a credentials file:
  `ai-env creds status`), 5 (no Touch ID in time, a move's too, no sealed token or runtime key, or
  Anthropic refused the token), 7 (AWS, or an image older than S8 or S9: the line names what it lacks,
  `make deploy`), 8 (the VM is gone, or its connection stayed lost, and since S10 the chat could not
  move: past `[vm] max_readdress` moves, a pinned VM, or a move that failed at 8 (stage S10); reopen
  the chat from the picker), 9 (a policy refusal:
  a scan finding, not a git repository, `[vm] max_concurrent` (a closed chat's suspended VM counts until
  its suspended time or its wall runs out, and since S10 so does a parked chat's; the line names the
  suspended VMs no open chat holds: `ai-env vm terminate ID` frees a slot; `vm gc --yes` ends only
  expired VMs), the credential gate, a refused environment name, and since S9 a transcript over the
  64 MiB a reopen carries or pulls (run what the line names in a terminal:
  `ai-env session stage UUID --warm`, after `ai-env session migrate-s9 --yes` for an S8 mirror, and
  with `[vm] reuse_per_workspace` set to true first when it is off) or a local resume of a remote
  chat's view), 143 (stopped before the session started).
- `Subprocess initialization did not complete within 60000ms`: nothing answered `initialize` within
  60 s. The wrapper gives up at 50 s, with an exit and
  `did not start within Cursor's 60 s window (stuck at STEP)`, so this means it hung: the census end
  row's `legs` show the slow step, and `ai-env vm warm WORKSPACE` before the chat takes the VM's start
  and the seed out of the window. An egress that refuses or cannot reach api.anthropic.com adds about
  20 s to every chat's `initialize`, whatever the legs say (claude retries its managed-settings and
  policy-limits fetches before it answers): `ai-env egress status`.
- `Nothing to resume for session UUID on channel N; starting a new conversation` (Cursor's Output
  panel): the Mac holds no view of that chat (since S9 its file here is the view: none was written yet,
  or `session gc --remote --yes` or `session forget --purge` removed it): see
  `ai-env session show UUID` and the wrapper's log.

The census records each session twice. The start row notes `mode:remote(config)` (`mode:remote` when
`AI_ENV_BRIDGE_MODE` set it) and, for `auth status`, `prewarm:spawned(PID)` or `prewarm:skipped(WHY)`;
the end row adds `vm`, `vm_how` (started, reused, resumed, pinned), `spawn`, `vm_pid`, `claude`, `legs`
(touchid, select, workspace, gate and spawn, in ms), `init_ms`, `credential` (where the session's
token came from: combined or setup-token for one the wrapper unsealed, with the runtime key's Touch ID
or with one of its own, cached when the wrapper counted on the VM's copy and sent none; a token goes to
the VM only with claude's spawn there, so a start that ended while connecting to the VM can name its
source though nothing was sent, or cached though the VM had lost its copy (exit 5,
`credential not on the VM`): `ai-env creds status` lists the VMs that may hold the token),
`seed` (seeded, updated,
up_to_date, kept), `transcript` (S9: kept on the VM, restored from S3, staged from this Mac, or none),
`mirror_dropped:N` (S9: transcript frames a remote child sent anyway, dropped; only when N is above 0),
`fetch` (the fetches
that succeeded, of those asked for), `close_ms`, `link_drops`, `auth_timers` and `pid_rewrite` (S10
adds the moves' and the parks' parts: stage S10), and for
a session that never started its `step`; a start row refused for a view notes `view_refused:resume` or
`view_refused:continue`. Under `~/.config/ai-env/bridge/`, `logs/wrapper.log` holds the
wrapper's notes and warnings (Cursor never shows them), `logs/ai-env.log` the CLI's, and `audit.jsonl`
the sessions' rows (`session_remote_start`, `session_remote_end`, `session_remote_failed` with its step
and why, `vm_select`, `seed`, `seed_refused`, `codeout_fetch` (S9: with `via`, `codeout` or
`smart-http`), `box_fetch_finding`, `settings_capture`, `settings_sync`, `prewarm`,
`auth_timers_unmeasured`, and S9's `transcript_push`, `transcript_pull`, `transcript_view`,
`transcript_stage`, `transcript_gc`, `transcript_migrate`, `box_review`, `hook_install` and
`drop_transport`, and S10's rows of the moves, the parks and the reaper (stage S10); never a URL or a
transcript byte; the S4 to S7 rows a session
writes carry purpose `session` or `prewarm`). `AI_ENV_BRIDGE_VM=ID` in Cursor's environment pins its
chats to one VM, checked before any Touch ID. `ai-env session drop-transport UUID` closes a running
remote chat's connection from the wrapper's side, and the chat reattaches (part B's check of T8.6).

```sh doc-test
ai-env wrapper census --last 4   # the newest start and end rows
ai-env lab list                  # the probes, touchid-gui among them (the prewarm needs prompted)
```

**The VM's CLAUDE.md.** Every VM starts with this `~/.claude/CLAUDE.md` (`image/claude/CLAUDE.md`):

```text vm-claude-md
# This machine

- You run in a disposable AWS Lambda MicroVM as uid 1000, at the same path as the developer's checkout on their Mac.
- The checkout came from the Mac: the current branch at its HEAD (a shallow clone, without the earlier history), with the developer's uncommitted changes applied but not committed. Do not discard them.
- Commit your own work to the current branch in small steps. After every turn the Mac fetches your commits, and a snapshot of uncommitted files, into refs/remotes/box/*; nothing is pushed, and this clone has no origin.
- The developer's editor shows the Mac's copy of each file, which changes only when they merge your work: name the files you changed.
- IDE tools (diagnostics, open editors, diffs) are not available here.
- Do not install system packages or change the machine's configuration. The network reaches only the Anthropic API, crates.io and the hosts the developer allowed.
- Never write credentials, tokens or keys to disk, into commits, or into command lines.
```

Debug builds also honour `AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip`: a resumed remote session's first start
restores no transcript (since S9 from S3; the wrapper's retry always restores), so the CLI's resume
miss, the wrapper's retry and its replay happen live (part B's duplicate probes).
`AI_ENV_BRIDGE_LAB_AGENT_ADDR` (S6) now carries the workspace routes on 8080 and 9418 too. The
wrapper's log records both: the transcript knob as `skip_transcript`, the agent address in the
`LAB KNOBS ACTIVE` line the CLI prints on stderr. S9 adds two: `AI_ENV_BRIDGE_LAB_S3_ADDR` (a loopback
fake S3 at `ip:port`, with the fake API only) and `AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES` (1 to 15: the
minutes of a code-port token, for the live re-mint test). The live Makefile targets drop them all, but
`make test-aws SLOW=1` then sets `AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2` for its test process, which
mints the re-mint test's tokens itself (the `vm`, `box` and `session` commands and the chats it runs
drop every lab knob); release builds compile them out.

### Pushes reviewed, transcripts in S3 (stage S9)

**What changes.** What a VM did comes back as S8 brings it, and a review now stands between it and any
push: `ai-env box review` checks what a push would carry, and a pre-push hook runs that review on every
push from the checkout. A remote chat's transcript no longer comes to the Mac at all: claude writes it
in the VM, the VM copies it to S3 after every turn, and the Mac keeps only a view of its last 10
messages, which Cursor's history lists and reopens; a reopened chat is restored from S3 into whichever
VM serves it, with its whole context (one over 64 MiB reopens only on a VM that holds it: the one it
ran on, or the one `ai-env session stage UUID --warm` restored it into). S9's image serves both (its
`/health` names `git_http_v1` and `transcript_s3_v1`): a remote session never reuses a VM of an older
image, and one it cannot do without
(a pinned VM, or one it started of an older image version) is exit 7 naming `make deploy`, as is
`box fetch --smart-http` there. Until `ai-env egress check` passes again after S9's `make deploy` and
`make infra-status WRITE=1`, a remote session stops earlier, at the credential gate: exit 9 before any
Touch ID, since a pass recorded before S9's S3 cases no longer counts (a pinned VM whose recorded caps
show an older image is exit 7 earlier still).

**Review before a push.** `ai-env box review REV` reviews the commits a push of REV would carry: those
REV holds and the bases lack (`--base REV`, repeatable; by default every remote-tracking ref but ai-env's
`refs/remotes/box/*` and `box-quarantine/*`; with none at all, the whole history, which a note says). It
runs the seed's tripwires over every object (blobs, commit messages, path names, a blob over
`[seed] max_blob_mib`), then judges each change at the commit that made it: the repo settings rules (D8)
on the settings files the range brings, and `allow-not-in-policy` for an allow entry that neither the
merge base nor `settings-policy.txt` holds; the dotenv rule; and the Cargo rules, `cargo-lock-removed` (a
commit deleting a `Cargo.lock`, a link put in its place, or a lock gone against the base or against the
tip a forced push replaces), `cargo-lock-source` (a new `source =` that is not crates.io),
`cargo-lock-checksum` (a checksum changed for an unchanged version) and `cargo-config-source` (a source
replacement, a `[patch]`, a `paths` override or an `include` in cargo's configuration; the file an
include names is reviewed as that configuration). A lock emptied of the packages its base pinned counts
as removed, and a lock or a cargo configuration the review's TOML reader cannot read (cargo reads TOML
1.1) is a finding at the file, as is a settings file it cannot read as JSON. A watched file behind a
link (a `Cargo.lock`, `.cargo`, `.claude`, a settings file or a dotenv pointing elsewhere in the tree, a
link the base already holds included) is reviewed where the link leads, under the watched name. Where
git runs the pre-push hook from the work tree (`core.hooksPath` naming a directory of the checkout), any
change on the way to it is a finding too (`pre-push-hook-changed`), and so is a change to a git
configuration file the repository reads from its work tree (an `include.path` to a tracked
`.gitconfig`), which can move `core.hooksPath`. git's replace refs (`refs/replace/*`) never stand in for
what is reviewed: the review reads the objects a push sends. It prints the commits' subjects
(control characters stripped; a subject that trips a rule is withheld, naming the rule), at most 20
finding lines naming the file, the line and the rule, never the value, then `box review: pass` or
`box review: findings` (exit 9). No AWS call, no Touch ID; `--json` prints one document, and each review
is audited (`box_review`).

**The pre-push hook.** `ai-env box hook-install [REPO]` writes a `pre-push` hook where git runs hooks
(`core.hooksPath` honoured), mode 0755, naming this `ai-env` by its absolute path; `--dry-run` prints the
path and the body and writes nothing. From then on every `git push` from that checkout first runs
`ai-env box review --pre-push`: each pushed range is reviewed against the remote's old tip and that
remote's tracking refs (not those when the remote has two or more push URLs: git moves them after the
first), and only a pass lets the push go; a report the hook could not write (a closed pipe) never lets
a finding through. Before it reviews anything it refuses (exit 9)
a push of a ref under `refs/remotes/` or `refs/ai-env/` (a `box/*` ref, any `--mirror` push) and a push
to a remote named `box` or `box-quarantine`. A push to a bare URL is reviewed against the tips it
replaces only, and the URL (git passes it as the remote's name too, credentials and all) is never
printed or audited. The hook fails closed: once the `ai-env` it names is gone, every push is refused
until `ai-env box hook-install` writes it again. It never replaces another hook: `hook-install` then
exits 1 and prints the two lines to put first in that hook, before any `exit` or read of its stdin (they
read the pushed refs once and feed them to the review; the hook's own readers take them the same way,
`printf '%s' "$ai_env_refs" | git lfs pre-push "$@"`); a hook of ours naming another `ai-env`, or no
longer executable, is written again. A hook in the work tree, or a git configuration file
there that can move it, gets a warning (a merged or checked-out commit can replace it, and committing
such a change is itself a review finding).
`ai-env doctor` has a row per workspace: `[ok ]` installed; `[!! ]` missing, another hook or not
executable, each with its fix, or in the work tree (the warning above, with no fix to run).
`box fetch` names a workspace without the hook once.
The hook is a control, not a wall: `git push --no-verify`, a push from another clone and a hook git does
not run all go out unreviewed, and the tripwires are tripwires, not proofs.

```sh doc-test
ai-env box review BRANCH            # what a push of BRANCH would carry: no AWS call, no Touch ID (exit 9 on a finding)
ai-env box hook-install WORKSPACE   # the pre-push hook: every push from the checkout is reviewed first
```

**Fetching through git smart-HTTP.** `ai-env box fetch --smart-http` fetches over git's smart-HTTP
protocol (version 2, upload-pack only) through the MicroVM endpoint, in place of `POST /codeout`. The
client is ai-env's own, over its own HTTPS (TLS 1.3, Amazon roots, no proxy, no redirects, a refused
token minted again once), so no token ever enters a git process; in the VM `git http-backend` runs as
the agent behind two literal routes (the advertisement and upload-pack), and a push to the VM
(receive-pack) is 403 before anything starts. It lists the VM's `HEAD`,
branches, `refs/wip/*` and seed snapshot, and asks only for what the Mac lacks; what comes back goes
through S8's import unchanged (the scans, `box/*` or `box-quarantine/*`, one transaction), no tag ever
reaches the Mac, and a ref with a credential-shaped name or naming no commit is left out and counted. It
is opt-in: the per-turn fetch stays on `/codeout`, and `--smart-http --wip` is exit 2 (the snapshot is
`/codeout`'s). An answer in protocol v0 is exit 1 naming the `protocol-v2` probe
(`ai-env lab run protocol-v2`; `chunked-put` records what the endpoint does with a chunked body).
`--dry-run` lists the refs only, and neither dry run records a token on the VM's row.

**Transcripts in S3, never on the Mac.** In remote mode the Mac no longer receives a chat's transcript:
claude in the VM runs without `--session-mirror`, and a mirror frame that arrives anyway is dropped and
counted. After each turn, beside the code-out, the wrapper syncs the chat: the VM pushes what its
transcript gained, and its subagents' files, to S3 through URLs the Mac presigns for one object each
(300 s, with the length, the sha256 and `If-None-Match: *` signed: every object is written once, checked,
and never overwritten). The Mac records the parts in `state/transcripts/UUID/manifest.toml`, then writes
the chat's view; it never reads an object back. No transcript URL is printed, logged or audited: each
travels to the VM in a request body behind the session bearer, and there curl runs as uid 999
(`ai-env-net`) with the URL on its fd 3, out of the agent's reach. `ai-env session sync UUID` syncs one
chat now (one Touch ID). Before this Mac ends a running VM (`vm terminate`, `vm gc --yes`) it syncs the
chats it holds (at most 60 s for them all; `[vm] auto_gc` does the same); a suspended one is ended as it
is, never woken: what a turn added after the last sync went up at its `/suspend` (since S10 a line
written after that push goes up too, through the next tail of a chain: stage S10). What a turn adds
after the last sync goes up from the VM itself at `/suspend` or `/terminate`, through a URL signed ahead
for an hour, without the length or the sha256 it cannot know (the main transcript only: a subagent's
file changed after the last sync is lost). That URL is handed as soon as the chat has its id and again
before each turn (since S10 at every unpark too, and the VM keeps it until S3 has answered its push),
so a chat closed before its first sync still goes up whole; until that sync its view is a
placeholder (`Remote chat`) that Cursor lists and reopens. A chat whose subagent and tool files pass 256
files or 256 MiB is synced without them (said once); a file synced once is never dropped from S3 by a
later sync.
Reopening a chat restores it beside the seed: on the VM it ran on, which holds it (`transcript:kept`),
else from S3 into the new VM (`restored`, at most 64 MiB: big chats below), every part checked before the file is renamed into place (a
part that fails leaves the VM's copy as it was). Its subagents' files follow once claude has started,
outside the reopen's time limit; one the VM holds newer than S3's copy is kept. The store is the bucket `ai-env-transcripts-ACCOUNT`
(versioned, encrypted, public access blocked, TLS only, objects under `v1/UUID/`); old versions expire
after 30 days and unfinished uploads after a day, but a current transcript stays until
`session gc --remote --yes` or `session forget --purge` removes it, and `make destroy` deletes the
bucket.

**The view.** The chat's file under `~/.claude/projects/` is its view: the last 10 messages (a user
prompt, or one assistant reply collapsed into one entry; `[transcript] view_messages`, 1 to 50), built in
the VM from the transcript's tail. It carries text only: a tool call reads `[tool: NAME]`, an image
`[image]`, and thinking, tool results, sidechains and subagents are left out. The Mac checks the VM's
answer strictly (an unknown key refuses the whole view, and the old one stays), passes every block, the
title and the branch through the session's tripwires (a block with a hit reads
`[ai-env: masked, rule RULE]`; a title or a branch with one is left out), sets the session and the
paths itself (an id or a time it cannot take is made anew), and writes the file atomically, keeping
Cursor's own `custom-title` lines.
Every line it writes starts with `{"aiEnvView":1,` (Cursor's `custom-title` lines, kept after them, do
not), so the first line alone tells a view from a transcript. Cursor lists the chat from it and shows
where it ended; the model, resumed in a VM, has it all.

**A view never resumes on the Mac.** A `--resume` or `--continue` of a view exits 9 on every route but
the remote one (passthrough, a session outside the roots, the local pump modes), and under the kill
switch too, which reads the first 4 KiB of that one file and nothing else (no config, no census):
`this chat's transcript is kept in S3; the file here is its view (the last messages only) and cannot be resumed on this Mac: reopen it with remote mode on, or start a new chat`.
Two runs never pass through the wrapper and would load a view as if it were the chat: a terminal's
`claude -c` or `claude --resume`, and Cursor's own claude while the wrapper is off. A window reload with
the wrapper off (`wrapper uninstall --write`, the reload, `install --write`, as under "No wrapper at
all") resumes every open chat on this Mac, so close the remote chats' tabs first;
`ai-env wrapper uninstall` says so while views exist:
`N remote chats keep only their view under DIR: with the wrapper off, Cursor resumes an open one on this Mac; close their tabs first`.

**Chats begun on the Mac.** A chat begun on this Mac goes up the first time it reopens remote: its
transcript and its subagents' files are scanned (a finding is exit 9 naming the file, the line and the
rule, and nothing is sent), sent to S3 by the Mac (`transcript:staged`), then moved to
`state/transcripts/UUID/origin/` and replaced by the view. A reopen carries up to 64 MiB inline; a larger
chat is refused before any Touch ID, exit 9:
`the chat's transcript is SIZE (over the 64 MiB a reopen carries inline): run ai-env session stage UUID --warm in a terminal, then reopen the chat`.
`ai-env session stage UUID` stages a chat of up to 4 GiB (what a restore pulls; since S11 4 GiB a
file and 16 GiB in all, each file gzipped: stage S11) from a terminal (one
Touch ID): scanned first, then a multipart upload (64 MiB parts, 8 at a time, a sha256 each; since
S10 a part is held to its progress, not to a timeout of the whole (stage S10), and a part that gets no
answer, or S3's 500 or 503, goes again, 3 tries at most) that resumes where a cut left it, never
sending again an object S3 holds; `--warm` then runs `ai-env vm warm`
on the chat's workspace (its own Touch ID), so the VM is up and seeded, and restores the chat from S3
into that VM (no Touch ID of its own), where its reopen keeps it (below). Before anything is sent it
refuses (exit 9) a chat whose transcript records a cwd outside `bridge.toml`'s roots or in no git
repository, which could never reopen once its file is a view (and exit 1 when it records none); a chat
that went on here after a cut stage is refused (exit 1)
and left as it is, the message naming the way out. The original stays under `origin/` until
`session forget UUID --purge`; there is no way back to a local chat, which would lose the VM's turns.

**Big chats.** Inside Cursor's window a reopen pulls at most 64 MiB of a chat's transcript from S3, its
parts and its last tail together: at the proxy's 4 to 16 MB/s a GiB takes minutes. A larger chat reopens
from a VM that holds it already (`transcript:kept`); any other reopen of it is refused before any pull,
exit 9:
`the chat's transcript in S3 is SIZE, over the 64 MiB a reopen pulls inline: run ai-env session stage UUID --warm in a terminal, then reopen the chat`.
The refusal comes before any Touch ID when what S3 committed is already over 64 MiB, no
`AI_ENV_BRIDGE_VM` pin is set and the reopen would start a new VM, which holds nothing: no VM row of
the chat's workspace is anything but terminated, or `[vm] reuse_per_workspace` is off (then the line
says `…, and [vm] reuse_per_workspace is off: set it to true, run ai-env session stage UUID --warm …`).
Otherwise it comes after the Touch ID, once the VM the reopen took shows it does not hold the chat (a
last tail can take a chat past 64 MiB too).
`ai-env session stage UUID --warm` makes such a chat ready: it warms the chat's workspace, then restores
the chat from S3 into that VM with no time limit, whatever its size (a `transcript_pull` row with its
bytes and ms; `--json` adds `restore`: the VM, the outcome, the bytes, the ms). Run again it pulls
nothing (`kept`). A chat begun on a VM takes `--warm` too: S3 holds it already, so nothing is staged,
and its registry row's cwd names the workspace. Reopen the chat while that VM lives (a suspended one is
resumed): once it ends, by its wall or `vm terminate`, the copy goes with it and the chat needs
`--warm` again. A reopen takes that VM only with `[vm] reuse_per_workspace` on and no
`AI_ENV_BRIDGE_VM` pin to another VM.

**S8's mirrors.** A remote chat from before S9 still has its mirror on this Mac.
`ai-env session migrate-s9 --yes` moves each into S3 and leaves its view: synced from its VM while that
runs S9's image (`transcript_s3_v1`), else uploaded from the scanned mirror, the view then built on the
Mac. A gone VM's mirror with a
finding is not uploaded: its view is built on the Mac (the hit masked), the mirror moves to `origin/`,
and the exit is 9 at the end, naming `session forget UUID --purge`. Without `--yes` it lists them, with
no AWS call and no Touch ID. A chat reopened before that goes up as one begun on this Mac when its
mirror is at most 64 MiB; a larger one is refused, naming `ai-env session migrate-s9 --yes`, then
`ai-env session stage UUID --warm` (once in S3 it is a big chat, above).

**Clean-up.** `ai-env session gc --remote --yes` removes the S3 transcripts of chats closed more than 90
days ago (`--older-than DAYS`), then their manifests and views; a Mac-begun chat's original stays. A
chat whose upload or first sync was cut before its manifest counts too, by the age of what it left in
`state/transcripts/`. Without `--yes` it lists them from this Mac's state (no AWS call, no Touch ID).
`ai-env session forget UUID --purge` also deletes one chat's S3 objects, its manifest, its original
under `state/transcripts/` and its view, after S8's checks (never while the chat runs); since S10 it
takes several ids, checks every one before it removes anything, and purges them all with one Touch ID
(stage S10).

```sh doc-test
ai-env session gc --remote --yes   # the S3 transcripts of chats closed over 90 days ago (without --yes: the list, no Touch ID)
ai-env session migrate-s9 --yes    # S8's mirrored transcripts into S3, their views left (without --yes: the list)
```

**S3 through the proxy.** A VM reaches S3 as it reaches everything, through squid, whose allowlist now
holds one AWS host, `ai-env-transcripts-ACCOUNT.s3.eu-central-1.amazonaws.com`, in the stack's own
`allow` list (never an extra). On its own, a tunnel to that host could still reach any bucket: a request
inside it may name another bucket, by its host or by its path (domain fronting), signed by any key the
agent can get, such as the execution role's, which IMDS hands it. So S3 is reached through a gateway
endpoint on the proxy's route table only (never the VMs'), whose policy admits our bucket's `v1/*` for
the runtime user of our account alone (and the AL2023 repositories the proxy's own `dnf` reads), and the
bucket's policy denies reads and the VM's writes from outside that endpoint, the Mac's writes through
it, and every other principal. `ai-env egress allow` still refuses every AWS service host (exit 9).
`egress status` checks the endpoint (exactly one, on the proxy's route table, its policy as deployed)
and the bucket (versioning, encryption, ownership, the public access block, its policy), and takes the
bucket's host in `allow` and no other AWS host. `egress check` adds seven cases (34 in all): our
bucket's PUT and GET through the proxy must pass (the GET's 200 proves the endpoint, since the bucket
refuses reads outside it), and these must be refused: a public object of another bucket asked through
our host, by name and path-style; a key outside `v1/`; the VM's own IMDS credentials
(`recorded:no_role` without an execution role); another S3 host; S3 without the proxy. Run it again
after S9's deploy: its record notes the rule it was judged by (`egress_rule = 1`). A pass recorded
before these cases (rule 0) counts neither for the credential gate nor for
`ai-env egress check --if-needed`, which runs the check again and says why.

**Also in S9.** `make test-cursor` needs `SINCE` (the step's start, taken with
`date -u +%Y-%m-%dT%H:%M:%SZ` before it, or `SINCE=all`): without it, exit 2 before cargo. doctor and
`wrapper status` name each open Cursor window still on another extension than the one installed, and
`infra pin --check-bundle` notes it beside its verdict; a session's settings diff can say
`no change since the start capture`; and F1 makes a mistyped bridge.toml fail remote mode closed (stage
S8 has the details). `ai-env-claude` exits 2 with its usage for a first argument that is empty, starts
with `-` (`--version`, `-V`, `--help` or `-h` alone still print and exit 0) or is a bare name other than
`claude` (CUSTODY-4: `ai-env-claude help` never runs the Mac's
claude), before any config read or census row; under the kill switch the first argument is still
exec'd as it is.

### Chats move to a new VM, idle chats park (stage S10)

**What changes.** A remote chat now outlives its VM. A lost VM (terminated, or no longer answering)
moves the chat to a new VM, with one Touch ID for the setup token and a note in the chat; a claude lost
on a VM that still runs restarts there, with no Touch ID while that VM holds the token; either way the
message the loss interrupted is sent again. Before its VM reaches the 8-hour wall a chat migrates to a
new VM between turns, with one Touch ID, and `ai-env session migrate UUID` does the same on demand. An
idle chat parks: the wrapper goes silent, the platform suspends the VM, and the next message resumes
it, with no Touch ID. None of it ends the chat Cursor runs: it keeps its process, its session and its
history. Moves work on S9's image too; parking needs S10's (its `/health` names `park_v1`): a chat on
an older VM never parks (`park:off(no_cap)` in the census) and keeps S8's keep-alive.

**A lost VM.** What ended the link decides, never a message's text:

- the VM was terminated (`vm terminate`, its wall, the platform) or is gone: the chat moves to a new
  VM once the old one is TERMINATED (at most 15 s), so the transcript's last tail, which a VM pushes as
  it ends, is in S3 before the restore;
- the VM stopped answering (its reconnect budget, 300 s, ran out: the shim down, the endpoint
  throttling): it moves too, once the old VM was synced (best effort, at most 10 s) and terminated
  (`vm_terminate` with `by` `readdress`), so that one no longer counts against `[vm] max_concurrent`;
- claude's spawn is gone, or a reattach found a replay gap, on a VM that still runs: claude restarts
  there (below);
- anything else (a newer client took the session, a refused hello or token) ends the chat as in S9,
  and so does any loss of a chat that is closing, or of a session that keeps no transcript.

The move asks its Touch ID at once, while it picks the VM: the workspace's other VM when one can be
reused (never the lost one), else a new one. The new VM gets the lost VM's work as this Mac last
fetched it (the branch, its commits and the snapshot of its uncommitted files at the last turn's end);
this Mac's checkout instead when that VM had nothing of its own (its last fetched head in this Mac's
history, no uncommitted files), and also, with a note, when nothing was ever fetched from it. Then
the transcript comes from S3, and claude starts with `--resume`, cut just before the interrupted
message when the transcript holds it (`--resume-session-at`); the message is sent again, and its turn
runs again from the prompt. A permission prompt left open is withdrawn (Cursor dismisses it, and the
turn asks again), and an interrupt you sent goes again after the message. The chat shows a note, a
line Cursor renders that never reaches claude or the transcript (wrapper.log keeps a copy):

`ai-env: this chat's VM ID was lost (it was terminated); moving the chat to a new VM (Touch ID for the setup token); the interrupted message is sent again; files are as of the last turn's end`

(`it stopped answering` for a VM that did), then, once claude runs on the new VM:

`ai-env: the chat continues on ID; background tasks and MCP servers did not survive the move`

A loss with no turn in flight waits for your next message, so you are there for the Touch ID; the
chat's row says `detached` meanwhile, and the note reads:

`ai-env: this chat's VM ID was lost (it was terminated); the chat moves to a new VM with your next message (Touch ID for the setup token)`

A loss mid-turn, or before Cursor's `initialize` was answered, moves at once. A move loses what the
lost VM did after its last turn's end (an edit made after the last answer, which no fetch took), the
interrupted turn's partial work (it runs again), background tasks, MCP servers and the old VM's file
history (no rewind across a move). It also misses a branch switch or a HEAD move that made no new
object (`git checkout -b topic`, a reset to a commit this Mac already has): the turn's fetch finds
nothing new, so this Mac keeps the record of the fetch before, and the new VM gets that fetch's branch
and HEAD (no commit is lost). Since S11 a VM of image 13.0 answers such a fetch with its manifest
alone, and the record follows the switch (F1, stage S11); an older VM still misses it. What was fetched stays under
`refs/remotes/box/*`, as before.

`[vm] max_readdress` (3; 0 to 10) bounds the moves after a lost link in one wrapper process, to a new
VM and on the same one (a migration counts none). With 0 a lost VM ends the chat as in S9 (exit 8);
past the limit it ends with exit 8 and:

`lost the VM ID after 3 moves in this session ([vm] max_readdress): reopen the chat from the picker`

A move has 180 s to get claude running (one that starts before Cursor's `initialize` was answered
keeps the start's 50 s). One that fails ends the chat with the exit of what failed (3 a dismissed
Touch ID, 5 none in time, 7 to 9 the new VM, its seed, the restore or the spawn) and this line, the
failure's own in the middle:

`the chat's VM ID was lost (it was terminated); moving the chat to a new VM failed: …; reopen the chat from the picker`

One loss is one move and at most one new VM: a VM lost twice makes two. A chat pinned to a VM
(`AI_ENV_BRIDGE_VM`) never moves off it: a lost VM ends it as in S9, and only a restart on the pinned
VM runs. Several chats on one lost VM move each with its own Touch ID, to one new VM when they can: a
VM whose checkout changed since its seed (another chat's) keeps it as it is (`seed:kept`,
`another chat moved here first`).

**A lost claude on a live VM.** A replay gap, or a gone spawn (a reattach found it ended, or its detach
grace ran out while the link was down), on a VM that still runs: the wrapper stops what is left of that
claude and starts it again there, cut and sent again as above:

`ai-env: this chat's claude on ID was lost (its spawn is gone); restarting it there; the interrupted message is sent again`

(`a replay gap` for a gap; with no turn in flight it waits:
`ai-env: this chat's claude on ID was lost (its spawn is gone); it restarts there with your next message`).
It asks no Touch ID while the VM holds the token (`touchid` `cached`); every suspend and resume empties
the VM's copy (S7), so a restart after a park asks one. It moves to a new VM instead, with that move's
Touch ID, when the VM no longer runs, when the gapped claude does not stop within 3 s, or when the chat
has had no answer yet (it starts again under its session id, `--session-id`, which needs a VM without
that chat's file).

**Migration before the wall.** A VM lives at most `[vm] max_duration_s` (8 hours), running and
suspended together. After an answer, when the chat's VM has less than `[vm] migrate_before_wall_s` left
(1200 s), the wrapper prepares a new VM while the chat goes on:

`ai-env: moving the chat off ID (its 8-hour wall): Touch ID for the setup token; the chat goes on meanwhile`

That one Touch ID, the new VM (never the old one), the credential gate and the token's delivery run in
the background, and the prepared VM is kept running for up to 15 minutes. At the next quiet point (no
message in flight, no prompt open either way) the wrapper switches: the old claude ends, the old VM's
work is fetched with its uncommitted files and the chat synced to S3, the new VM is seeded from that and
the transcript restored, and claude resumes there with nothing sent again (`the chat continues on ID`,
as above). The old VM is synced and terminated afterwards (`vm_terminate` with `by` `migrate`) unless
another chat's claude still runs there; until it ends, no new chat reuses it.

A dismissed or unanswered Touch ID keeps the chat where it is and asks again after the next turn:

`ai-env: the chat stays on ID (no Touch ID in time); it tries again after the next turn`

A new VM that cannot be prepared for another reason (`[vm] max_concurrent` reached, the gate), or a
second switch that fell back, ends wall migrations in that wrapper process (the note then ends
`it moves when the VM reaches its wall`): the wall is the backstop, and the chat then moves as from a
lost VM. A switch that fails after the old claude stopped restarts claude on the old VM (one more Touch
ID when a suspend emptied that VM's copy of the token). A pinned chat never migrates.
`migrate_before_wall_s = 0`, or one at or above `max_duration_s`, turns migration off; 1 to 59 is
refused, and a value over half of `max_duration_s` puts a line in wrapper.log: a VM would migrate in
the first half of its life.

With migration on, reopening a chat whose VM is within `migrate_before_wall_s` of its wall moves the
chat before it starts: a new VM, never the old one, seeded from a fetch of the old one run beside the
new VM's start (from its last fetch when too little of Cursor's 60 s window is left), the chat synced
there too; the old VM is terminated afterwards (`carried:migrate` in the census). A reopen whose VM is
gone, or past its wall, starts on a new VM seeded from that VM's last fetch (`carried:readdress`).
Both stay within the reopen's own start and its usual Touch IDs, and count no move against
`[vm] max_readdress`. For a chat over the 64 MiB a reopen pulls inline, a VM near its wall no longer
counts as one that holds it (stage S9's big chats: `ai-env session stage UUID --warm` first).

**Moving a chat on demand.** `ai-env session migrate UUID` moves a remote chat to a new VM now,
whatever its wall:

- with the chat open (its wrapper runs, an S10 one), the command leaves a request
  (`state/sessions/UUID.migrate.json`) and signals the wrapper (SIGUSR1), which prepares the new VM at
  once (its Touch ID, shown by the wrapper) and switches at the chat's next quiet point, as above; the
  command waits for the answer, at most 300 s;
- with the chat closed, the command moves it itself, with one Touch ID, the runtime key's alone (the
  chat's next reopen delivers the token): the old VM resumed, fetched and synced (its last fetch when
  it is gone), a new VM, the seed and the restore with no time limit, the chat's row pointed at the new
  VM (its `vms` gain `migrate:command`), and the old VM terminated, synced first, unless another chat's
  claude still runs there. Meanwhile a reopen of the chat exits 1
  (`session UUID is being moved to a new VM (pid N): reopen it in a minute`), and `session forget`
  refuses it.

It prints `session UUID: moved from ID to ID (live)` (or `offline`), and with `--json` one document
(`session`, `outcome`, `how`, `from_vm`, `to_vm`, `ms`, `code`). Before any Touch ID it refuses a chat
on this Mac (exit 9, `session UUID runs on this Mac: there is no VM to move it from`), an unknown chat
or one with no VM (exit 1), a move another command asked in the last minute (exit 1,
`a move of session UUID was asked N s ago (pid N): wait for it`), and an open chat whose wrapper
predates S10, which SIGUSR1 would end (exit 1,
`session UUID's wrapper (pid N) predates S10: close the chat and reopen it, then run ai-env session migrate again`).
Its exits: 0 moved; 1 refused (another move under way, the chat closing, a pinned chat), given up
(the prepared VM's hold ran out, a loss moved the chat first, the chat closed), or no answer within
300 s (the wrapper may still move it at the chat's next quiet point); 3 or 5 the Touch ID (dismissed,
or none in time); 7 AWS; 8 the wrapper exited before it answered; 9 a policy refusal (the credential
gate). Migration off does not stop it, and it is the way out of a move whose seed was too large for its
window (exit 9, naming it).

**Parking.** After `[vm] park_after_s` of quiet (unset: `[vm] max_idle_s`, 300 s) a chat parks: no
message in flight, or only a permission prompt waiting for your answer; no line either way; claude's
own output quiet; the turn's fetch and sync done. The wrapper asks the VM's shim to park claude, then
stops its pings and its keep-alive, and the platform suspends the VM about `max_idle_s` later, with
claude in it as it was. The next message, or the prompt's answer, unparks it: the wrapper reconnects
(the endpoint resumes a suspended VM) and hands the line on, with no Touch ID (the runtime key is in its
memory, and claude kept its token in its own). Several chats on one VM each park on their own, and the
VM suspends only once all are silent. `ai-env session list` shows a parked chat as `parked`.

The shim refuses a park while the chat's processes are at work: more than 300 ms of CPU in a 10 s
sample, a process running (one the agent detached included) or any stdio, within the last 30 s; the
wrapper asks again after `park_after_s`. A build or a test run therefore keeps its VM up and finishes.
What waits quietly is frozen with the VM and goes on only when it resumes: a timer, a `sleep`, a
server, a job waiting on the network.

A suspend under a working chat (`ai-env vm suspend ID`) no longer ends it after
`[transport].suspend_wait_s`: the chat waits for your next message, which resumes the VM. Closing a
parked chat whose VM is suspended returns at once and wakes nothing (`close_parked:1`): its claude
stays parked in the VM's snapshot until the next chat started on that VM ends it, or the VM ends. A
parked chat whose VM ended meanwhile (its wall, `[vm] suspended_s`, `vm terminate`) moves to a new VM
at its next message, as from any lost VM. `[vm] park = false` keeps S8's keep-alive: an open chat's VM
never idles, and a suspend under it waits `[transport].suspend_wait_s`, then exits 8, as `vm exec` and
`vm attach` do.

**The setup token in a parked VM.** A parked chat's VM is suspended with claude, and with the setup
token in claude's memory, in its snapshot. That is S7's accepted invariant (a VM given the token may
hold it until it is TERMINATED), now the everyday case. The shim's own copy is still dropped at
`/suspend`, which is why a restart after a park asks a Touch ID where an unpark asks none.
`ai-env creds status` lists the VMs that may hold the token, and `ai-env vm terminate --all --yes` at
the end of a day ends them.

**Bounds and clean-up.** A parked chat's VM runs at most `park_after_s + max_idle_s` after the chat's
last activity (10 minutes at the defaults), then sits suspended (its snapshot kept, nothing running)
until the next message, `[vm] suspended_s` or the wall, whichever comes first. A suspended VM still
counts against `[vm] max_concurrent`, and the refusal names the ones no open chat holds:

`3 VMs already run ([vm].max_concurrent, suspended ones included): parked with no open chat: ID; ai-env vm terminate ID frees a slot, then reopen the chat`

(`ID (+N more)` when there are more). Each chat's wrapper reconciles the registry 10 s after its start,
at most every 15 minutes across them all: a VM row whose VM the platform ended is marked terminated,
old terminated rows go, and a session row whose VM is gone and whose wrapper is dead is closed; it
never terminates a VM and never asks a Touch ID (`vm_gc_reconcile`). `ai-env vm list` (without
`--json`), `vm run` and `vm smoke` run the same reconcile every time. Before claude starts on a VM (a
reopen, a move), the wrapper ends that chat's claude left by a wrapper that is gone (`leftover`) and
every parked claude whose wrapper is gone (`orphan`), within 2 s each (`session_reap`): two claudes
never share one transcript. A leftover that does not stop fails the start, exit 8
(`this chat's claude from an earlier wrapper (spawn UUID) did not stop on ID`).

**The keys** of bridge.toml's `[vm]`, at their defaults:

```toml
[vm]
max_readdress = 3            # 0..=10; 0: a lost VM exits 8 as in S9
park = true                  # false: never park (S8's keep-alive)
# park_after_s = 300         # 30..=3600; unset: max_idle_s
migrate_before_wall_s = 1200 # 0, or max_duration_s or more: no migration; 1 to 59 refused
```

A value out of its range fails every `vm` and `lab` command, a remote chat's start (exit 1) and doctor's
`[vm]` row, naming the key. An S9 build refuses a bridge.toml that sets `max_readdress`, `park` or
`park_after_s` (it reads `migrate_before_wall_s`, which S9 uses only to stop reusing a VM near its
wall): take those out before going back.

**The Claude account a chat runs as.** Every start of claude takes the active Claude account at that
moment, the one `credentials/setup-token.env` holds (`ai-env creds account use NAME` installs one, with
no Touch ID): a new chat, a move's new VM, a restart on the same VM, a migration's new VM (its account
is the one installed when the migration's Touch ID was asked) and the old VM a migration falls back
to. A running claude keeps its account until its next start, and a retry keeps the account of the
start it retries: a resume miss's (it asks no Touch ID), and a move's on the same VM while that VM
still holds the token. A restart on a VM that already holds the new account's token asks no Touch ID;
one whose VM holds the old one asks one, for the new token. A chat that now runs as another account
says so, right after the note that it goes on:

`ai-env: the chat now runs as Claude account NEW (it ran as OLD): the active account since ai-env creds account use`

A turn refused for the account's usage limit reaches the chat as claude printed it
(`You've hit your weekly limit · resets …`), and a note follows it, naming another account to go on
with (the one with the lowest weekly use ai-env saw, a week whose reset has passed counting as 0 %, else
one it saw with no weekly use known, else one it never saw, which the note says; never one whose token
Anthropic refused, which `creds account use` would refuse) and how:

`ai-env: account NAME hit its weekly limit (it resets 10am (UTC)); to go on now with account OTHER: ai-env creds account use OTHER, then reopen this chat or run ai-env session migrate UUID`

A pinned chat, or one started with `--no-session-persistence`, cannot move, so its note offers only
the reopen. When every other account is limited or refused, as far as ai-env knows (or when which
tokens were refused cannot be read), the note says so and names `ai-env creds account check`; with no
other account, it names `ai-env creds account add NAME`. What a
turn's `rate_limit_event` says of the account's 5-hour and weekly windows, and a limit, go into
`[usage.NAME]` in `state/accounts.toml` (written at once for the first, a limit, a change of status or
the first answer after a limit, else at most once a minute, and never waiting for the file's lock). A
limit whose reset time claude did not give counts for at most its window (5 hours for the session
limit, else a week) from when it was hit. With no account at all (one token sealed with
`ai-env creds setup-token`), there is no note and no `[usage.NAME]`, and no record names an account.

**What the records say.** A remote chat's census end row adds `moves:readdress=N,respawn=N,migrate=N`
once a move started (a reopen's carry counted too), with `move_ms` (the last move's) and `cut` (`none`,
`at` or `fresh`: how the moved claude resumed); `carried:readdress` or `carried:migrate` for a reopen
that moved first; on every remote row `inits:F/S` and `echoes:F/S` (claude's inits and message echoes
forwarded to Cursor and swallowed: a respawn's or a move's duplicates never reach it); `ka_dropped:N`
(Cursor's `keep_alive` lines dropped while parked; only when N is above 0); `park:N`, or
`park:off(no_cap)`, `park:off(config)` or `park:off(no_owner)`; `park_refused:N`, `parked_s`,
`unpark_ms` (the slowest unpark), `unpark_resumed:N` (unparks that found the VM suspended) and
`close_parked:1`; and `end:move_failed` with `step` for a chat whose move failed. `audit.jsonl` adds
`session_move` and `session_move_end` (the kind, the cause or the trigger, the VMs, where the seed
came from, the transcript, the cut, whether a Touch ID was asked, the ms, and the outcome: `done`,
`failed`, `stayed`, `abandoned` or `refused`), `session_migrate_request`, `session_park`, `session_unpark`,
`session_park_refused` (at most one per 10 minutes per chat), `session_reap` and `vm_gc_reconcile`;
`vm_select` gains the generation and the VM it avoided, `seed` its source (`box`, `mac`, `kept`),
`session_remote_start` why its VM started, `vm_terminate` the reasons `readdress` and `migrate`, and
the closing suspend's `vm_suspend` its outcome, why it was skipped and its ms, so a missed suspend
shows. A session row's status is `active`, `detached` (the link down, or a loss waiting for the next
message), `parked`, `migrating` (a move under way) or `closed`, and its `vms` list each VM the chat ran
on, across reopens (the newest 64), with why it started (`first`, `retry`, `readdress:vm_gone`,
`respawn:spawn_gone`, `migrate:wall`, `migrate:command`, `migrate:reopen`, …), how it ended and the
wrapper's pid. Whether Cursor showed a move's note is recorded by hand after a move:
`ai-env lab run move-note --manual shown` (or `not-shown:WHAT`). The end row also adds
`rate_limit:SEEN/WRITTEN` once claude printed a `rate_limit_event` (the lines seen, and those recorded
for an account) and `usage_limited:N` once a turn was refused for a usage limit; `audit.jsonl` records
each such turn as `usage_limited` (with the account, `-` when none holds the token). With Claude
accounts, the end row adds `account:NAME[,NAME…]` (the accounts the chat's starts ran as, in order);
`audit.jsonl` adds `session_account` (a start on another account than the one before it), and names
the account in `session_remote_start`, `session_move_end` (with `account_from` when it changed),
`credential_unseal` and `credential_deliver`; the row's `vms` entries name each start's account.

```sh doc-test
ai-env session list               # each chat's status: active, detached, parked, migrating or closed
ai-env session show UUID          # its VM, and in vms each VM it ran on: why it started, how it ended
ai-env wrapper census --last 4    # the end rows' moves, cut, inits, echoes and park parts
ai-env vm list                    # the VMs, a parked chat's suspended one too; then the registry reconciled
ai-env doctor                     # the [vm] row: the memory baseline and the guest's MemTotal ([NO ] naming a key out of its range)
```

**Also in S10.**

- `ai-env session forget UUID... --purge` takes several chats: every id is checked first (a refusal
  names its id, and nothing is removed), then one Touch ID purges them all (S9 asked one per chat).
- A line a chat writes after its VM's `/suspend` pushed the transcript's tail is no longer lost
  (stage S9's gap): the shim keeps a tail URL until S3 answered its push, the wrapper hands the next
  tail of the chain before each turn and at every unpark, and a reopen restores the whole chain. An S9
  build cannot read a chat's manifest that records such tails: its reopen, sync, gc and
  `forget --purge` fail there until S10 is installed again.
- `ai-env session stage UUID --warm` with `[vm] reuse_per_workspace` off is refused before any Touch ID
  (exit 9, naming the switch); a pinned reopen of a chat over 64 MiB in S3 names `AI_ENV_BRIDGE_VM`
  (unset it, then `--warm`).
- Code out scans the new objects of all the branches a fetch brings as one, and reads their settings
  files in one walk of their trees; a branch's own scan runs only after a finding, with the same
  findings as before (in an S9 test a fetch of 2100 branches took 96 s).
- The S3 uploads (`session stage`, a reopen's inline stage) are held to their progress, not a budget
  of the whole: a try fails once its body hands nothing for 60 s, or its answer's head is 120 s late, or
  a chunk of the answer 60 s late; S3's 409 `OperationAborted` and `ConditionalRequestConflict` and its
  400 `RequestTimeout` go again; a Complete whose answer was lost counts once S3 lists the object; an
  upload below 1 MB/s warns once.
- In the VM, each subagent file a reopen restores has a time budget that allows for the files pulled
  beside it, sharing the VM's link (S9 budgeted each as if alone), and a transfer slower than 1 KiB/s
  for 60 s fails; the seed record survives a shim restart; `/suspend`'s snapshot and tail push finish
  when the hook's client goes; the run report and `/health` carry the guest's `MemTotal`.
- `ai-env doctor`'s `[vm]` row reads the memory as
  `2048 MiB baseline (the image's minimum; bursts to 4×, billed while used)`, with the guest's
  `MemTotal` beside it once a VM's `/health` named it; the quota row sums baselines.
- `init-wrapper` judges a reused VM's start against 5 s and a resumed one's against 8 s (stages S1–S2,
  above), and a resume polls the VM at 200, 300 and 500 ms before its 1 s steps.
- The census keeps a `--max-thinking-tokens=` of 1 to 7 digits as written (anything else is still
  masked), and `make proxy-patch` names squid's version after the patch even when the document's
  output is cut.
- The image build fails when its claude binary lacks a string a move relies on
  (`--resume-session-at`, `--session-id` and their errors); since S11 an admission checks every new
  version for the same strings, its markers (stage S11).

**What the first S10 measurements found** (taken before S10's image was built, on image 11.0 and
claude 2.1.302; `plans/s10-measurements.md`). At rest claude used at most 50 ms of CPU in any 10 s
sample at a permission prompt and 70 ms after a turn; it wrote nothing to stdout, and Cursor sent
nothing between turns. So the shim refuses a park only above 300 ms a sample, a parked claude's output
is not held, and Cursor's `keep_alive` lines are dropped while parked as a guard (no `ka_dropped` part
is the norm: it is written only above 0). A fresh VM's first claude answers `initialize` about 0.6 s
later than a warm one (it pages in 142 MiB of its 272 MiB binary, and makes two fetches it then
keeps), on a second fresh VM just the same; the rest of the binary reads at 6.5 to 14.5 MiB/s, so no
warm inside the VM would help, and the image does none.
The slow cold starts S8 and S9 saw (17 to 20 s) were claude's fetch retries while the egress was down
(`ai-env egress status`). The guest's `MemTotal` read 8016 MiB against the image's 2048 MiB minimum.
The live tests on S10's image read the park figures again on claude 2.1.303, from the census's `park`
parts.

```sh
make test-aws S10=1            # S10's live tests (live_s10_*): a close and a reopen, a lid's sleep, a VM terminated mid-turn
                               #   and one after an edit, a park at a permission prompt then subagents across a move,
                               #   session migrate (about 21 Touch IDs)
make test-aws S10=1 SLOW=1     # + the three wall tests: a wall migration, a reopen near the wall, a reopen after it (about 30)
make test-cursor STEP=t10_3 SINCE=TIME   # one S10 Cursor step's evidence (t10_2, t10_3, t10_4, t10_5, t10_p), in a fixture window
```

Debug builds also honour `AI_ENV_BRIDGE_LAB_PARK_AFTER_MS=<n>`: the park's quiet in n ms (1 to
3600000) in place of `[vm].park_after_s`, with or without the fake API. The live Makefile targets drop
it, and release builds compile it out.

### Claude always fresh, the panel, the audit and the cost (stage S11)

**What changes.** Cursor's auto-update stays on, and ai-env follows it: a new Claude Code version in
the Cursor extension reaches remote chats with no deploy. ai-env checks the new version first (its
release signature against a vendored key, then the Docker tests), stages its Linux binary in S3
through a VM that holds no credential, and the VMs fetch it from there. Until a version has passed
both checks and is staged, chats run the newest version that has, or the image's own claude
(`image/claude.lock`, 2.1.305), as before. Leave Cursor's Auto Update on: no ai-env row or line
advises turning it off, and a version skew blocks nothing (the deploy's preflight P10 shows it as a
note, `[-  ]`, and `ai-env infra pin --check-bundle` exits 3 with the note). S11 also brings a local
control panel, a reader for the audit, a cost estimate rebuilt from the audit, new doctor rows, and a
compressed `session stage`. Its image is 13.0: an older VM keeps running chats on the image's claude.

**When Cursor updates the extension.** Nothing to do. What happens:

1. Cursor installs the new extension (the bundle `anthropic.claude-code-V-darwin-arm64`, V the
   version); a window runs it once reloaded. `ai-env claude status` names V `seen`, and doctor shows
   a `[!! ]` row naming the next step, never a `[NO ]`.
2. In remote mode the first wrapper that sees V (Cursor's `auth status --json` when a window opens, or
   a remote chat's start) starts `ai-env claude admit V --auto` detached, with no Touch ID and nothing
   in Cursor's way, when `[claude].auto_admit` is on (the default), this Mac's record of V is missing,
   not past `signed`, or `failed(docker)` with attempts left (step 3), the last try for V ended more
   than 15 minutes ago (`state/claude/V.lock` holds its outcome) and an `ai-env` sits next to the
   wrapper. The admission then needs Docker answering, cargo on its PATH (Cursor's), this checkout and
   the local image `ai-env-agent:local` (`make image-build-local`); without one it records nothing,
   and the lock says which (`skipped(no_docker)`, `skipped(no_cargo)`, `skipped(no_checkout)`,
   `skipped(no_image)`). In passthrough nothing starts it: run `ai-env claude admit`.
3. The admission (no Touch ID, no AWS call): the release's `manifest.json` and its signature, checked
   by `gpgv` against the vendored key alone; the Linux arm64 binary, downloaded and checked against the
   signed size and SHA-256; its markers (texts the code relies on, the strings a move needs among
   them); then `make claude-admit-docker`, this checkout's claude-facing Docker tests run on that
   binary in `target/claude-admit` (the first build takes several GB and many minutes, a later one 2 to
   5 minutes), with no key in its environment. The verdict goes into `state/claude/V.toml`: admitted,
   or `failed(STEP)`, which stands until `ai-env claude admit V --redo`, but for `failed(docker)`: a
   Docker run that failed (a busy Mac's load can fail one) is tried again by the automatic admission,
   up to 3 attempts in all, 15 minutes apart, each attempt checking every step again (the signed
   manifest, the binary's size and SHA-256, its markers) before the tests. The record counts the
   failures and keeps the failing tests' lines and first panic (`ai-env claude admit V --json` shows
   them; the next run writes `logs/claude-admit-V.log` anew); `ai-env claude status` and doctor name
   the first failing test, the attempt and when the next one may start, or that the attempts are
   spent. A refused signature, binary or marker is never tried again by itself, and `--redo` runs
   whatever the count. A step that may pass again (the network, gpgv missing) records nothing. The
   tests run on the working tree: no edit in the checkout while an admission runs, or it fails
   (`failed(docker)`: tried again 15 minutes later, or `--redo`).
4. The stage (one Touch ID, the runtime key's): a stager VM (`--egress internet`, no credential, 900 s,
   purpose `claude-stage`) streams V's release from downloads.claude.ai into an S3 PUT the Mac presigned
   with the signed length, the SHA-256 and a new-only condition, so S3 takes no other bytes; the Mac
   never uploads the binary. The object is `v1/_claude/mac/V/SHA256` in the transcripts bucket. `ai-env
   claude stage` or `update` stages by hand; `vm warm` (the installed bundle's version) and, in remote
   mode, the wrapper's prewarm (its window's, once per version) stage an admitted version not staged
   yet inside their own Touch ID. The stager counts against `[vm] max_concurrent`.
5. The fetch: a VM of image 13.0 fetches V from S3 into its cache (`/opt/ai-env/claude/SHA256/claude`,
   root's, run as the agent, 2 binaries kept) after a chat's first output (or 20 s after its start), at
   most 32 MB/s, and keeps it only when its size, its SHA-256 and its `--version` match. Nothing waits
   inside Cursor's 60 s window: a chat that starts on a VM lacking V runs what that VM holds, and the
   next start there runs V. `vm warm` (waiting up to 120 s), the prewarm, `session stage --warm` and a
   migration's preparation fetch ahead. A VM that finds the object's bytes wrong has the Mac delete it
   and mark V `stale` (the next stage restages it); a second bad stage in a row is `failed(stage)`.

**Which claude a chat runs.** A remote chat's start names V when it is staged, then the other staged
versions, newest first, at most 4 in all; the VM runs the first one its cache holds, else the
image's claude. The census end row says what ran (`claude:VERSION`) and where it came from:
`claude_src:cached` (V from the VM's cache), `image` (the image's claude, which is V), `older(WHY)`
(another cached version, a newer one for an older window too) or `image(WHY)` (the image's claude,
which is not V), WHY the first reason V did not run: `no_ext` (no version in the extension's path),
`seen`, `failed`, `not_staged`, `not_cached` (staged, not on that VM yet), `no_cap` (an image older than
13.0), `bad` (V failed to start on that VM before) or `start_failed` (it just did). `ai-env wrapper
status` shows the newest remote chat's. Two restarts ask no Touch ID: a claude that refuses an option
the extension passed (`error: unknown option …` before it answered `initialize`) starts again on the
same VM without it (at most 3 options a chat, never one a session needs; census `argv_dropped:FLAG`,
audit `argv_dropped`), and a cached claude that dies before it printed anything starts once more with the
next claude (audit `claude_start_failed`; the VM's row keeps it as bad); neither restarts a claude
that printed anything. A chat reopened on a VM that lacks the version its transcript was written by is
resumed by another claude, which `claude_src` shows. When a reconnect cannot learn which claude a
start ran (its `spawned` answer lost with the socket), the end row has neither part.

**The commands.** These two ask nothing of AWS and no Touch ID:

```sh doc-test
ai-env claude status   # each version's phase (seen, signed, admitted, failed, staged, stale), who runs it, the image's fallback
ai-env claude gc       # what gc would delete, from the records (without --yes nothing is deleted)
```

`ai-env claude admit [VERSION] [--redo]` admits (the installed bundle's version by default; no Touch
ID; exit 9 when the signature, the binary or a marker refuses it, 1 when the Docker tests fail or a
step may pass again). `ai-env claude stage [VERSION] [--force]` stages an admitted version (one Touch
ID; exit 9 before it for a version not admitted, or at `[vm] max_concurrent`; an object S3 already
holds, its `412`, counts as staged). `ai-env claude update [VERSION]` admits when needed, then stages
(one Touch ID). `ai-env claude forget VERSION` deletes its S3 object (one Touch ID; none with
`--local`, which leaves S3 as it is), its binary on this Mac and its record, and refuses a version a
live Cursor window runs unless `--force`. `ai-env claude gc --yes` keeps in S3 the 3 newest staged
versions, the bundle's and every live window's, deletes the others' objects (one Touch ID), and keeps
the 2 newest binaries on this Mac. Their audit rows are `claude_admit` (with `auto` for the wrapper's,
and a Docker failure's `attempt` and first failing `test`) and `claude_stage`; the VMs' fetches write
`claude_fetch` and `claude_object_bad`.

**Doctor, wrapper status and the pin.** One row per version the installed bundle or a live window
runs, newest first, never `[NO ]`: `[ok ]` when chats run it (staged, or the image's own claude),
else `[!! ]` naming the claude chats run meanwhile and the next command (`ai-env claude admit`,
`stage`, or `admit --redo` after a failure; a Docker failure's row names its first failing test and
its attempt, then the automatic retry and from when, or that the attempts are spent); then
`[-  ] the image's claude 2.1.305 runs where no staged version can`. S10's image
claude row and its Auto Update advice are gone. `ai-env infra pin --check-bundle` says
`pin: lock 2.1.305 is the image's fallback; Cursor bundle V: VMs follow it (ai-env claude status)`
with exit 3 (equal: exit 0; no bundle or no readable lock: exit 1), and the deploy's P10 shows that
note as `[-  ]`. `make claude-pin CLAUDE_VERSION=V` moves the fallback (`ai-env claude manifest`
fetches and verifies the manifest first, fail-closed), which then needs a deploy; the image stays on
2.1.305 until a reason to move it.

**The vendored key.** `crates/ai-env-cli/certs/claude-code-release.asc`, fetched once from
`https://downloads.claude.ai/keys/claude-code.asc`, and its dearmored `claude-code-release.gpg`, which
is compiled into ai-env: `gpgv` (Homebrew's, never one found on PATH) gets a copy of it as its only
keyring. `certs/README.md` records both files' SHA-256s and how the key was checked, and tests tie
the compiled keyring to that record and the fingerprint, `31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE`,
to the Makefile's `CLAUDE_GPG_FPR`. Only a good signature whose valid signer is that fingerprint
passes; a bad, expired, revoked, unknown or missing signature, or any other answer, fails the
admission closed. gpgv comes with GnuPG (`brew install gnupg`; the preflight's P4 names it). If
Anthropic rotates the key, every admission fails until the key is vendored again (after checking the
new one out of band, as `certs/README.md` says), and chats keep the newest admitted version.

**The panel.** `ai-env panel serve` serves a control panel in the foreground until Ctrl-C (or SIGTERM,
SIGHUP; exit 0). It is off until `[panel] enabled = true` in bridge.toml (else exit 9), listens on
127.0.0.1 only, at `[panel] port` (7391; `--port N`, 0 for any free port; a port in use is exit 1),
refuses any other `--bind` (exit 2) and any bound address that is not loopback (exit 9), and costs no
Touch ID to start. It prints its URL once on stdout, `http://127.0.0.1:7391/BEARER/`, BEARER a fresh
value per run (32 random bytes, 43 characters), never written to disk, never in an argv or a log, and
known to the scrubber, so no line ai-env writes holds it. Open the URL in a private browser window (its
history would keep the bearer), and never paste it into a chat, a file or a screen share. Every
request must carry it as the path's first segment (compared in constant time, else 401), with `Host`
exactly `127.0.0.1:PORT` (else 403: no DNS rebinding); only GET, HEAD and POST pass, a GET's
`Sec-Fetch-Site` (when sent) must be `same-origin` or `none`, and a POST's `Origin` must be the panel's
own and its `Sec-Fetch-Site` `same-origin` (else 403), its body a small form (else 413 or 415). Every
answer carries a strict Content-Security-Policy, `no-referrer`, `X-Frame-Options: DENY`, `nosniff` and
`no-store`, and never a cookie or a CORS header. The pages, rendered on the Mac with every value
escaped (each also as JSON with `?json=1`): Sessions (VM, moves, cost), a session (its generations,
moves, timeline and cost), VMs (with RUN and COST), Audit (live, at most 8 streams), a session's
settings diff (read-only) and Cost. The actions: suspend, resume and terminate a VM, refresh the list,
and migrate a chat. Each goes through a confirm page that names its CLI twin (`ai-env vm suspend ID`,
…) and issues a nonce bound to it, single use for 5 minutes; one action runs at a time (another gets
409), each asks its own Touch ID from the panel's process, and its rows say `actor=panel`. A live
chat's migrate is its wrapper's move, with that move's Touch ID. The Run button posts through the
page's script (a plain form post under `no-referrer` would carry no usable `Origin`, and gets 403).
The panel's start and stop are audited (`panel_serve`).

**The audit.** `audit.jsonl` is at schema v2: every row's `detail.actor` says who wrote it (`cli`,
`wrapper` or `panel`; the wrapper's detached `vm warm` says `wrapper`, `claude admit --auto` `cli`), and
a registry of every event (87, with their keys, the key that names a VM, where the session comes from
and what each means for the cost) is frozen in `tests/fixtures/audit/schema-v2.json`: names and keys
are never renamed. S11's events: `claude_admit`, `claude_stage`, `claude_fetch`, `claude_object_bad`,
`claude_start_failed`, `argv_dropped`, `vm_observed` (a VM seen in a new state) and `panel_serve`;
`vm_run` gains `max_duration_s`, `max_idle_s`, `suspended_s` and `memory_mib`, `transcript_stage`
gains `stored`. `ai-env audit tail` prints the last rows (20, `-n N`) one per line, `TS ACTOR EVENT
SESSION8 VM K=V…`, every cell scrubbed again and its control characters escaped (`--json`: the rows
as stored); `-f` then follows the file (Ctrl-C ends it, exit 0), across a truncation too. The filters
(all must hold): `--session UUID` (its rows, and its VMs' rows while it ran on them), `--vm ID`,
`--event E,…`, `--actor cli|wrapper|panel`, `--since WHEN` and `--where K=V` (repeatable); a malformed
one is exit 2. `ai-env audit grep PATTERN [-i]` prints the rows whose line holds PATTERN, a fixed string
(not a regex; a session's full id matches its rows too, though the line shows its first 8 characters),
and exits 1 when none does. Neither asks AWS anything or a Touch ID; an S10 row (v1, no
actor) is read as well as it can be.

```sh doc-test
ai-env audit tail --session UUID   # one chat's rows, and its VMs' while it ran on them
ai-env audit grep ID               # every row naming that VM; exit 1 when none does
```

**The cost.** `ai-env cost` estimates what the MicroVMs and the egress proxy cost over a window
(`--since WHEN`, default 24 h before now; `--until WHEN`; `--by day` splits it at UTC midnights;
`--json`), rebuilt from this Mac's audit alone: no AWS call, no Touch ID. WHEN is `90s`, `30m`, `1h`,
`2d` before now, an RFC 3339 UTC time or a UTC date. Each VM's running and suspended stretches come
from its run, resume, suspend and terminate rows and its chats' keep-alive spans; an idle suspend no
row records is inferred `max_idle_s` after the last activity, which makes the estimate a range. They
are priced at S10's measured Lambda rates (per vCPU-second of the 1 vCPU baseline, per GB-second of
the image's memory, per GB of snapshot written, read and stored), plus the proxy's EC2 lines, each
line under its Cost Explorer usage type. Not counted: S3, CloudWatch, data transfer, image builds,
and the VMs of another bridge root (the live tests'); the output says so beside its caveats.
`ai-env cost --compare FILE` judges the estimate against a Cost Explorer answer over the file's own
days (`aws ce get-cost-and-usage … --group-by Type=DIMENSION,Key=USAGE_TYPE`, which an identity
that reads billing runs: none of ai-env's may; the output prints the exact line): the MicroVM total
passes within ±30 % (T11.1), and exits 1 outside it. The views carry it too: `vm list` gains RUN and
COST, `session list` the VM, MOVES and COST, and `session show` the generations, the moves (each
paired with its end), the timeline and the cost.

```sh doc-test
ai-env cost --since 7d   # the last week's estimate and its range: no AWS call, no Touch ID
```

**The doctor matrix.** Every broken precondition of the wrapper path is a `[NO ]` row naming its fix
(a sibling `ai-env-claude` missing or of another version: the install; Cursor's wrapper setting on a
path that does not exist or does not run: `ai-env wrapper install --write`, after the install when the
sibling is missing). S11 adds: `ai-env = ai-env-claude = image shim` (the deployed image's shim, from
`state/infra.toml`, of another version is `[NO ]` naming the deploy, or the install when the image's
is newer; a live VM on an older shim is `[!! ]` naming that chat's migrate, or the VM's terminate);
the `image/` scan of the checkout doctor runs in (a finding is `[NO ]`; a deployed zip that is not the
one the scan passed is `[!! ]`); the stack's budget, its limit and what was spent, `[!! ]` once the spend
reaches the limit (under `ai-env as ops --`: ops reads it with `budgets:ViewBudget`, which S11's deploy
grants); newer versions of the managed
base image; and `[!! ]` rows for a workspace root that does not exist, an `initialPermissionMode` of
`bypassPermissions` (every chat would start with no permission prompt) and an `[aws].image_version`
pinned to another version than the active one. The claude rows (above) replace S10's image claude row.

**The drift rows.** Doctor reads the census's chat rows of each running Cursor window's extension,
offline, names and flags only, never a value: `[!! ]` for env names it starts chats with that
`[wrapper] env_forward` and `env_extra` do not forward and no review has classified (`ENV_REVIEWED`,
`src/bridge/drift.rs`), `[-  ]` for a forwarded name it no longer sets and for a name a remote session
never carries (one `vm exec` refuses, such as a TOKEN name), `[!! ]` for flags the router
does not classify (add them to `VALUE_FLAGS` or `BOOL_FLAGS` in `src/wire/argv.rs`, then
`make argv-fixtures EXT=V`), and per extension newer than 2.1.302 whether its reader still names the
view's fields (`[ok ]`, else `[!! ]`: the view format changed). They replace S10's fixture-drift row.

**The compressed stage.** `ai-env session stage` now stores each file as `/usr/bin/gzip -n -6` of its
scanned bytes (`Content-Encoding: gzip`), keyed by the stored bytes' SHA-256; the manifest keeps the
decoded length and SHA-256 beside the encoding and the stored ones. Subtree files go up 8 at a time,
and the caps are 4 GiB a file (what one pull restores) and 16 GiB in all, decoded (S9's was 4 GiB the
chat). The VM's pull decodes (curl's `compressed`) and checks the decoded bytes. A gzip-staged chat
reopens only on a VM whose image decodes it (`transcript_gzip_v1`, image 13.0): a reopen takes no
older VM for it, and an S10 build cannot read its manifest. A reopen's inline stage gzips only for a
13.0 VM. `transcript_stage` records the stored bytes (`stored`) beside the decoded ones (`bytes`). A
chat that goes on here while it is being staged is refused once its manifest is written (exit 1): its
files stay where they are, and `ai-env session forget UUID --purge`, then `ai-env session stage UUID`,
stages it with every turn.

**S3's other prefixes.** Beside the chats' `v1/UUID/`, the transcripts bucket holds
`v1/_claude/mac/V/SHA256` (the staged claudes: `ai-env claude gc` and `forget` delete them) and S9's
`v1/_egress-check/` (it expires by itself). A sweep of `v1/` by hand for chats no session owns skips
both prefixes; `session gc --remote` and `session forget --purge` never touch them.

**Also in S11.**

- F1: a branch switch or a HEAD move that brings no new object (`git checkout -b topic`) now moves the
  chat's fetch record on a 13.0 VM (`codeout_manifest_v1`), so a move carries the new branch.
- C-4: a move during the first turn after a `/compact` resumes cut at the compaction (`view_parent_v1`,
  a 13.0 VM) instead of sending that turn again after its partial answer; on an older VM it still does.
- `make test-aws S11=1` runs S11's live tests (`live_s11_*`) alone, and `make test-aws S10=1 WALL=1`
  S10's three wall tests alone.

```sh
make test-aws S11=1            # S11's live tests (live_s11_*): the stager, claude_src after a fetch, an unknown option,
                               #   F1 after git checkout -b, C-4 after /compact, a fork's first write
make test-aws S10=1 WALL=1     # S10's three wall tests alone (about 45 minutes)
```

### Identities: the deployer, ops and the runtime key

The AWS side has three IAM users, all made by Pulumi and none with a key in Pulumi (see the S3 notes
above). Every command that calls AWS runs as one of them, and the account root only for the
bootstrap and break-glass (below):

- **The deployer**, `ai-env-deployer`, changes the stack: `make deploy` and `make preview`, the
  stack's five IAM policies (`make deploy-policies`), every access key (its own, ops' and the runtime
  user's), image versions and connectors, and `ai-env egress allow`; it holds everything ops may do
  too. Inside the account it is admin-equivalent, so the protection is its key, which lives only in
  its Strongbox entry (`ai-env-deployer`, in Strongbox's own encrypted database) and in no file
  ai-env writes. A command that needs it asks once for that entry's two fields, at two no-echo
  prompts on the terminal, clears the clipboard, and checks the key with sts against the stack's
  account before anything runs.
- **Ops**, `ai-env-ops`, runs the daily operator commands: the egress and proxy commands but
  `egress allow`, `make infra-status`, `make gates`, the read-only image, connector and log targets,
  `ai-env lab run cloudtrail-payload` and doctor's AWS rows. It may start and stop the proxy
  instance, send it the three proxy documents, write the `suspended` list and read what those
  commands read. It may not send any other document or reach any other instance, write `extras`,
  `allow` or `squid.conf`, make any IAM write (its own key included), pass a role or deploy. Its key
  is sealed in `credentials/ops.env` under the bridge keystore key, like the runtime key: one Touch ID
  per command outside a runner, none under `ai-env as`.
- **The runtime principal**, `ai-env-runtime`, is unchanged: VMs and Cursor sessions, its key in
  `credentials/aws.env` (and `combined.env`), one Touch ID per credentialed `vm`, `box` or wrapper
  command. Since S9 it also signs the transcripts' S3 requests: objects under `v1/` of the transcripts
  bucket of its own account only, and no other principal may read or write them.

**The runner.** `ai-env as IDENTITY -- CMD ARGS...` replaces itself with the command, run as one
identity (the command's exit status is the runner's): `deployer` (the key pasted, as above), `ops`
(`credentials/ops.env`, one Touch ID), `root` (the shell's own credentials, which must be the
account root's: the bootstrap and break-glass only) or `ambient` (the shell's own credentials,
declared and never the root's; their account and rights are not checked, so it is only for an
agent's read-only session in another account, never for credentials of the stack's account).
Under `deployer` and `ops` the command gets the key in `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` and nothing that could select other credentials: `AWS_PROFILE`, session
tokens, role and web-identity variables, `AWS_CONTAINER_*` and `AWS_ENDPOINT_URL*` are removed,
`AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` point at `/dev/null`, IMDS is off and the
region is pinned. It also gets the marker `AI_ENV_BRIDGE_AS` (`deployer:ABCD` or `ops:ABCD`, the
key id's last four characters, or `root`, or `ambient`), which only `ai-env as` sets (never export
it by hand): a nested `ai-env as`, or a make target, whose identity the marker covers runs at once,
with no prompt, no Touch ID and no audit row (the deployer covers ops, root covers both, ambient
covers ops and ambient), and a key marker whose key is no longer in the environment is refused
(exit 9). A nested `ai-env as root` is refused under every marker, root's own included, and so is
`ai-env as ambient` under any marker but ambient (exit 9: start it from a terminal of its own);
make's root tier checks `ai-env as --check root` first, so under the root marker it runs its target
without nesting one. `ai-env as --check IDENTITY` is make's guard: exit 0 when the marker covers it,
else 9. A fresh run writes an `as_identity` audit row and ends with one note naming the identity
and the command, such as `as ai-env-ops (key ...WXYZ, credentials/ops.env): make gates` (an
account shows as `…9012`); before it, `as deployer` asks for the paste and says it cleared the
clipboard, and `as root` warns when the stack already has its deployer. The runner's own exits: 1 a
malformed paste or the stack's account unknown (`--account` names it), 2 a usage error (a malformed
`--account`, no command after `--`), 3 cancelled, 4 no keystore key, 5 the key refused, no
terminal, no `ops.env` or no ambient credentials, 7 the deployer key's check failed otherwise, 9
another user, the root, another account or a marker it does not accept. While the command runs, the
key sits in the environment of its process tree, where the user's other processes could read it; it
is gone when the command ends. Never run a shell or another long-lived program under
`ai-env as deployer` or `ai-env as ops` (such as `ai-env as deployer -- zsh`): the key would stay in
its environment, and in everything started from it, until it exits. Put several goals in one make
run instead. The same holds for the stack's passphrase under
`ai-env run -f "$HOME/.config/ai-env/pulumi.env"` (below).

**Nothing falls back to the shell's own AWS settings.** Every `aws` call of an operator command (the
egress and proxy commands, `infra status` and `infra base-image`, `gates`, `creds aws-set --check`,
lab's `connector-pending` and `cloudtrail-payload`) runs as the runner's identity, else as ai-env-ops
from `credentials/ops.env` (unsealed once per process, with the note
`operator ai-env-ops (key ...WXYZ, credentials/ops.env)`), else not at all: the command stops with
exit 5 and `no AWS operator identity: …` (`infra status` still writes and exits 0: its live reads
are skipped and recorded as `live read failed: no AWS operator identity: …`). The shell's own
credentials (`AWS_PROFILE`, `~/.aws`, exported keys) count only when `ai-env as root` or
`ai-env as ambient` declared them, and must then be the account root's, or must not be. ai-env never
needs root's key after the bootstrap (only break-glass would), so a terminal used for ai-env holds
no credentials of the stack's account: a bare `aws` call there fails
(`Unable to locate credentials`), or answers as another account's default profile from `~/.aws`, by
design: run it as `ai-env as ops -- aws …`, or as the deployer for a write. Never paste root's env
into such a terminal, nor load root's key from the shell's startup files or the default profile of
`~/.aws/credentials`: the runners ignore it, but a plain `aws` call and anything else started from
that terminal would run as the root. The bootstrap and break-glass are the exception: they load it
without echo into a terminal of their own, closed afterwards (below). P8 of
`make s3-preflight PHASE=b`, which `make deploy` runs first, admits only the stack's deployer: the
account root only for the bootstrap or with `BREAKGLASS=1`, never ops, the runtime key or another
user.

**What each command asks for:**

- the deployer-tier make targets ask for the deployer's key once per top-level make run, after any
  build (the target's own build runs without the key): `deploy`, `preview` (`REFRESH=1` adds
  `--refresh`), `deploy-policies`, `runtime-key`, `ops-key`, `deployer-key`, `image-activate`,
  `image-deactivate`, `image-prune YES=1`, `image-delete`, `connector-probe`, `connector-delete` and
  `test-egress`; several goals share one paste under
  `ai-env as deployer -- make preview REFRESH=1 deploy`. `deploy`, `preview` and `deploy-policies`
  (and the root's `destroy`) also need the stack's passphrase: when it is not set they unseal it
  after the build and before their runner asks (the deployer's paste; `ai-env as root` asks for
  nothing), one Touch ID per goal (below). These targets never compile with the key or the
  passphrase:
  the tiered ones build first without it, `make test-docker` builds, runs Docker and tests without
  it (`image-zip` and `vm-build` build without it whoever calls them), `make install` builds
  without it, and `make test-aws` and `make test-aws-readonly` build their tests without it before
  they run with it. The other build and test targets (`build`, `test`, `lint`, the smokes) keep
  whatever key their shell holds, so put none of them after `ai-env as deployer --` or into the
  break-glass terminal (`make test-docker deploy` asks once anyway, after the build);
- the ops tier asks for one Touch ID: `image-wait`, `image-status`, `image-versions`, `image-builds`,
  `image-prune` without `YES=1`, `connector-status`, `connector-wait`, `logs`, `egress-logs` and
  `acceptance`, and the one-command targets `infra-status`, `gates`, `check-base-image`,
  `proxy-start`, `proxy-stop`, `proxy-patch` and `allowlist-reload`, whose one `ai-env` command
  resolves its identity itself, as `ai-env egress …` and `ai-env proxy …` typed by hand do; none
  asks again under `ai-env as ops --` or `ai-env as deployer --`;
- `ai-env egress allow` needs the deployer (`ai-env as deployer -- ai-env egress allow SLUG HOST`),
  and `ai-env egress check` costs the ops key's Touch ID and then the runtime key's for its VM;
  `ai-env claude update` and `ai-env claude stage` cost the runtime key's Touch ID, and
  `ai-env claude admit` none (stage S11, above; `make claude-update` is retired);
- `ai-env doctor` asks for nothing, and its one AWS call is a plain sts call that warns when the
  shell's own credentials are the account root's; `ai-env as ops -- ai-env doctor` (one Touch ID)
  adds the rows that call AWS: the operator identity (checked with sts), the deployer's key count
  (one is the norm), whether the account root still has an access key (a deactivated one counts),
  the proxy, the base image and the quota. The ops key row (from its file's notes: the user, the
  last four characters and the day it was sealed) and the deployer row show either way, and
  `ai-env creds status` shows the ops key and the deployer without a Touch ID;
- `make -n TARGET` (and `-q`, `-t`) asks for nothing: it shows the unseal (when it would happen) and
  the runner it would call, then the recipe. Every tiered target refuses `make -i` (a refused
  identity would be ignored) and `make -p` (`-n` beside it or not: make prints every variable when it
  ends, and the make under the runner would print the key, and the passphrase once unsealed), before
  its build, its unseal or its runner. A make typed under
  `ai-env as` (or `ai-env run -f` with the passphrase) holds the key (or the passphrase) itself and
  prints it under `-p` whatever the target, so never `-p` there. `make -j` is not for tiered targets
  (two runners would ask at once);
- `vm`, `box` and the wrapper's sessions are unchanged: the runtime key's Touch ID.

**The stack's passphrase.** Pulumi needs the dev stack's passphrase for `pulumi preview`, `up` and
`destroy` (reading the stack's outputs needs none). Seal it once per Mac into an ai-env container
under the bridge keystore key (`[creds].key`, `ai-env-bridge` by default), then set its value in
`ai-env edit`:

```sh
printf 'PULUMI_CONFIG_PASSPHRASE=\n' | ai-env encrypt -k ai-env-bridge - > "$HOME/.config/ai-env/pulumi.env"
ai-env edit "$HOME/.config/ai-env/pulumi.env"
```

In the editor: Enter on its line, the passphrase inside single quotes (taken literally), Enter,
`Ctrl+S`, `Ctrl+C`. If you paste it (from Strongbox, say), copy it with Handoff and any clipboard
history off, as for the keys, and clear the clipboard after the paste (`pbcopy </dev/null`). The
first line writes a new container over any earlier one: to change the value later, run only the
second. The file opens only on this Mac (its keystore key); a new Mac seals its own.

From then on the targets that need it unseal it themselves (`ai-env run -f` of that file, one
Touch ID) when it is not set as Pulumi takes it (`PULUMI_CONFIG_PASSPHRASE` first, even empty, and
an empty one counts as none; else `PULUMI_CONFIG_PASSPHRASE_FILE`): `make preview`, `make deploy`,
`make deploy-policies` and `make destroy` after their build and before their runner asks (the
deployer's paste; `ai-env as root` asks for nothing), saying so first
(`deploy: the dev stack's passphrase: ai-env run -f … (one Touch ID)`). Only that run holds it:
nothing compiles with it, and no test or Docker step sees it. `PULUMI_SEALED=FILE` (on the make
command line, or exported) names another file, a leading `~/` the home directory's (zsh passes `PULUMI_SEALED=~/…` on to make as it is). An exported
`PULUMI_CONFIG_PASSPHRASE_FILE` works as before, and with the passphrase set nothing is unsealed
(nor in a make nested in such a run). Without the file, `make deploy` and `make deploy-policies`
refuse before anything runs, naming the two lines above: their plan check runs Pulumi's preview `--non-interactive`, which cannot prompt; `make preview`
and `make destroy` keep Pulumi's own prompt. A sealed value left empty (the first line without
`ai-env edit`) stops the run right after the Touch ID, before the runner; a wrong one fails at the
plan check with Pulumi's `incorrect passphrase`, nothing deployed: set it again with `ai-env edit`.
Never put the passphrase, or its file, on the make command line: make refuses both there
(`MAKEFLAGS` would hand them to every child, the builds included; exported, they stay out of the
builds), and `make -p` would print them. Each a command of its own: pasted together, the later
lines could reach the deployer's key prompts.

```sh
make deploy
```

```sh
make preview
```

Several goals that need the passphrase unseal once each, as each asks for the deployer's key; under
this wrapper they take one Touch ID and one paste in all:

```sh
ai-env run -f "$HOME/.config/ai-env/pulumi.env" -- ai-env as deployer -- make preview REFRESH=1 deploy
```

**When the deployer lacks a right.** A deploy that stops on `AccessDenied` names the action. Add it to
`infra/policies.ts`, then run `ai-env as deployer -- make deploy-policies deploy` (one paste, and
the passphrase's Touch ID per goal; or one in all under the `ai-env run -f` wrapper of "The stack's
passphrase", above): the
deploy's gates, a `pulumi up` of the five stack policies alone, then the deploy. While the stack's
plan holds one of the five documents unknown, as it does whenever the proxy is to be replaced
(ai-env-ops' document names the instance), deploy-policies refuses before `pulumi up` (exit 1,
nothing deployed): its targeted `pulumi up` would render that document from the old instance and
apply what no check compared. Run `ai-env as deployer -- make deploy` instead: the whole plan
applies the new document with the rest. If a step still stops on that `AccessDenied` (it ran before
the policy step had landed), run the deploy again after about 15 s; break-glass is for a policy step
that is itself refused. The deployer may version its five policies but never create or delete one,
and may neither detach nor delete itself; the plan check refuses any replace or delete of its user,
attachments or policies, and any provider replace. G7 of `make gates` proves the split from
`state/infra.toml`, with no sts call of its own, so its verdict is the same whoever runs it: it
simulates ai-env-deployer (its four pairs allowed) and ai-env-ops (twenty deploy actions denied), and
is skipped until `make infra-status WRITE=1` has recorded the two users after the bootstrap.

#### The bootstrap

The full runbook, with what each step prints and costs, is part B0 of `plans/s8-operators-plan.md`.
In short: once, as the account root, with root's access key in one terminal of its own, for steps 1
and 2 only. Load it there with the `read -rs` line of Break-glass (below), which keeps it out of the
shell's history, never with an `export` that carries its values. Until the stack exports a
deployer, the deployer-tier targets run under `ai-env as root` (said on stderr) and ask for no
paste. Between `make install` and the bootstrap deploy the egress commands fail: the new ai-env
sends proxy documents the stack does not have yet. One command at a time:

1. `make test-docker deploy` (the stack's passphrase: one Touch ID, unless set): Pulumi creates the
   two new users, their two policies, six attachments and the three proxy documents, replaces the
   three deploy policies once (their descriptions changed; part B0 first checks that nothing holds
   them) and updates the image.
2. `make operator-keys` (the account root, once; a rerun resumes): the deployer's first key goes onto
   its Strongbox entry through the clipboard, is pasted back and verified, then ai-env-ops' key is
   sealed into `credentials/ops.env` and verified (one Touch ID). Before it, on this first
   hand-over, run `ai-env creds deployer-key --clipboard-check` with any clipboard manager or
   clipboard history off: its marker must not paste on another Apple device. If it does, hand nothing
   over by either route (the console's copies cross the same clipboard, unmarked): turn off Handoff
   (System Settings, General, AirDrop & Handoff) and check again.
3. Close the root's terminal, then in a new one: `make infra-status WRITE=1`, then the checks:
   `make gates` shows G7 ✓, and `ai-env as deployer -- make preview REFRESH=1 deploy` is the
   deployer's first run (one paste, no changes, and the passphrase's Touch ID per goal; or one in
   all under the `ai-env run -f` wrapper of "The stack's passphrase", above).
4. Root's access key: ai-env never needs it again (only break-glass would), so deleting it is
   optional. Delete it when nothing else uses it (IAM console as root, with MFA: Security
   credentials, Access keys); `ai-env as ops -- ai-env doctor` then shows
   `[ok ] the account root has no access key`, and warns `[!! ] the account root has an access key`
   while one exists (a deactivated one counts). While it exists, never paste root's env into a
   terminal used for ai-env, nor load it from the shell's startup files or the default profile of
   `~/.aws/credentials`: the runners ignore it, but a plain `aws` call and anything else started
   from that terminal would run as the root.

While root's key is live, it must not sit in the shell's history either: the `read -rs` line leaves
none there, but a pasted `export` does. This counts the lines of `~/.zsh_history` that assign its
secret (it prints a number only); above 0, close every other terminal (a shell writes its history
when it exits), then remove those lines in an editor:

```sh
grep -c 'AWS_SECRET_ACCESS_KEY=' "$HOME/.zsh_history"
```

#### Rotation

All three run as the deployer and ask for its key once; each creates the new key, seals or hands it
over, verifies it, and deletes the old one last:

- `make ops-key ROTATE=1`, which is also how a new Mac gets its ops key, once that Mac has the
  stack's Pulumi state (the local backend and `infra/Pulumi.dev.yaml`, from the old one) and
  `state/infra.toml` (copied too, or written by `make infra-status WRITE=1`, which writes it without
  an operator identity): `ops.sh identity` refuses while the stack's outputs cannot be read, and
  `ai-env as deployer` takes the stack's account from that file. The new Mac also seals the stack's
  passphrase itself (the two lines of "The stack's passphrase"): the old Mac's file opens only there;
- `make runtime-key ROTATE=1` (`credentials/aws.env`; `combined.env` is rebuilt, as before);
- `make deployer-key ROTATE=1`: the new key goes onto the Strongbox entry as with
  `make operator-keys`, and the old key it deletes last is the one the run was started with, so run
  it alone and paste the new one from then on.

A step that fails says what to delete or restore by hand. A bare `aws` call has no credentials of the
stack's account in a terminal used for ai-env, so every `aws iam …` line it prints starts with the
runner that can run it, the make target's own and the CLI's alike (the sealing check's two-key
refusal, the delete command of a key that was not stored or handed over): `ai-env as deployer --`
(one paste), or `ai-env as root --` when the run was the account root's (`make operator-keys`,
break-glass), to paste in its terminal. `ai-env creds forget --ops` lists, and with `--yes` removes,
`credentials/ops.env` and its backups, then prints the IAM commands that delete its key, already in
that form.

#### Break-glass

The account root is needed again only when the deployer cannot act (its Strongbox entry is lost, or
its own policies no longer let it fix them) and for teardown. Load root's access key into one
terminal of its own without echo (when none is left, create one in the console: as root, with MFA;
copy each value with its copy button and never download the .csv, with Handoff and any clipboard
history off); the line then clears the clipboard:

```sh
read -rs 'AWS_ACCESS_KEY_ID?root access key id: '; echo; read -rs 'AWS_SECRET_ACCESS_KEY?root secret access key: '; echo; pbcopy </dev/null; export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

Then run the one command needed, with `BREAKGLASS=1` on the make command line (exported, it is
ignored): for a lost Strongbox entry `make deployer-key ROTATE=1 BREAKGLASS=1`, when self-management
broke `make deploy BREAKGLASS=1`, for teardown `make destroy CONFIRM=destroy-dev BREAKGLASS=1`. The
target runs under `ai-env as root`, says so on stderr, and P8 shows `[-  ] P8 BREAK-GLASS: …`; a
deploy or a destroy unseals the stack's passphrase first, as without it (one Touch ID, unless set).
Destroy is the account root's alone, since it deletes the operator users themselves; its checklist
adds the two users, every `ai-env-*` policy, `credentials/ops.env` and the Strongbox entry, and ends
with root's key (item 15: unset, this terminal closed, the key deleted when nothing else uses it).
Afterwards, in the same terminal:

```sh
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

then close it. As after the bootstrap, deleting root's access key is optional: delete it when
nothing else uses it (a key created for this break-glass included); then
`ai-env as ops -- ai-env doctor | sed -E 's/[0-9]{12}/ACCOUNT/'` shows
`[ok ] the account root has no access key` (a deactivated key still counts). A teardown leaves no
ops key for that check: there, the IAM console shows what is left (as the root: Security
credentials, Access keys).

### Access-control policies (`keygen --access-control`)

`any-biometry-or-passcode` (default — Touch ID with password fallback; works in clamshell) ·
`any-biometry` · `any-biometry-and-passcode` · `current-biometry` (invalidated if fingerprints
change!) · `current-biometry-and-passcode` · `passcode` · `none` (testing only).

The Touch ID prompt fires once per decrypt operation; the enclave never caches biometry, so
`rekey` over N files means N prompts (it warns above 10).

### Key selection

Decrypt side needs no configuration: the file's `p256tag` carries a per-file tag computable
from each key's public recipient — `ai-env` matches it before any prompt. Encrypt side (new
files): `-k NAME` → nearest `.ai-env.toml` → the default key.

```toml
# .ai-env.toml — key names only, no secrets. Gitignore it or commit it, your call.
default_key = "myapp-devnet"

[[rules]]
paths = ["*.mainnet.env", "deploy/prod/*"]
key   = "myapp-mainnet"
```

## Editing (`ai-env edit`)

A secure form-style editor: variable **names** are listed, every **value** stays sealed
(masked) and is decrypted only while you edit it — **at most one value is ever plaintext in
memory**, inside a locked, guard-paged buffer. Values re-seal after 30s idle. `Enter`
reveals/commits, `Esc` discards, `a` adds, `r` renames, `d` deletes, `u` undoes (sealed
history), `Ctrl+S` saves (streams values one at a time into age — never a whole-file
plaintext buffer), `Ctrl+C` or `Ctrl+Q` quits (Cursor's and VS Code's terminals keep `Ctrl+Q` for
themselves).

The in-memory sealing follows OpenSSH's ssh-agent key-shielding design: an ephemeral 16 KiB
prekey in mlocked guard-paged memory, per-value XChaCha20-Poly1305 cells bound to their
variable name, 256-byte padding buckets. It defeats a **snapshot** adversary (core dumps —
also disabled outright, crash reports, forensic memory scans, swap images): a captured
snapshot contains at most one plaintext value instead of all of them. It does **not** defeat
a live same-user attacker (who could simply run `ai-env show`), the pixels of a revealed
value in your terminal emulator's memory, or screen capture. `edit` refuses to run under
tmux/screen (their server process keeps a copy of the drawn screen and outlives the editor;
`--insecure-terminal` overrides) and denies debugger attach for its lifetime.

## Git: commit the ciphertext

An encrypted `.env` is safe to commit — and committing it is what backs it up. Most repos have
a `.env*` ignore rule that now silently keeps the *encrypted* file untracked; `ai-env encrypt`
detects that and offers to add a `!.env` negation **plus a pre-commit hook that refuses any
plaintext `.env`** (so the negation can never leak an unencrypted one). Ciphertext changes
completely on every re-encrypt (fresh ephemeral key) — add `.env -diff` to `.gitattributes` if
the diffs annoy you.

## Honest limitations

- **Encrypting cannot un-leak the past.** The previous plaintext may live on in APFS snapshots,
  Time Machine, git history, editor backups, and shell history. Anything that was ever
  plaintext on disk should be **rotated**, not considered scrubbed. `ai-env doctor` flags
  plaintext `.env.backup`-style siblings.
- Decryption needs a GUI session (Touch ID cannot prompt over SSH). Encryption works anywhere.
- An app that loads the encrypted `.env` directly gets `AI_ENV*` metadata instead of its
  config — by design it *fails*, but only as loudly as the app checks its config. Use
  `ai-env run -- CMD` as the supported path, or guard on `AI_ENV` being set.
- Plaintext is capped at 46 KiB (docker's 64 KiB env-file line limit; `encrypt` warns at 32).
- macOS on Apple Silicon for keygen/decrypt (age-plugin-se's Homebrew bottle currently
  requires macOS 26 Tahoe). Encrypting to existing recipients works on any OS with `age`.
- `keys forget` removes local files only — Secure Enclave keys cannot be enumerated or
  deleted; the enclave slot is orphaned. Files remain recoverable via their recovery identity.
- A Claude account's usage, as ai-env knows it, is only as fresh as ai-env's last turn on that
  account: claude.ai, the desktop app and Claude Code sessions outside ai-env use the same limits
  unseen. `ai-env creds account check` measures (one turn and one Touch ID per account).
- Two live chats on one VM that run as different Claude accounts and start claude within the same
  moment can race on the VM's one credential slot: the second token delivered replaces the first
  before the first claude reads it, so that claude runs as the other account. Fixing it needs the
  image (the spawn naming the token it expects).
- A wrapper still running from before an `ai-env` with Claude accounts was installed (a chat left
  open across `make install`) fails its moves after a `creds account use` (the token was sealed anew
  under it: exit 5). Reopen such a chat.
- `ai-env cost` is an estimate from this Mac's audit: idle suspends are inferred, the GB a snapshot
  writes or reads and the proxy's rates are calibrated against Cost Explorer (T11.1), and bursts above
  the baseline go unseen.
- The panel's URL holds its bearer: a browser's history or a screen share can show it, and whoever
  has it on this Mac can start the panel's actions (each still asks its Touch ID) until the panel stops.

## Security invariants (enforced by tests)

- Exactly **one** identity is ever passed to `age -d` — age prefers native (software)
  identities over plugin ones, so a stray recovery key on disk would silently bypass Touch ID.
  ai-env never writes recovery secrets to disk, period.
- Wrong-key (`4`) and corrupt (`6`) exits are decided by ai-env's own parser *before* age is
  spawned — no prompt is ever shown for a file your keys can't open.
- Secrets never appear in argv; decrypted bytes for `run` live in a zeroized buffer and reach
  the child only through its environment.
- A MicroVM whose egress echo is not exactly what its egress requires is terminated and never
  returned, reused or adopted (S5); no credential enters a VM that `egress::credential_gate`
  refuses.
- An operator command's `aws` children run as exactly one identity: the key of the `ai-env as`
  runner, else the sealed `credentials/ops.env`; the shell's own AWS settings only when
  `ai-env as root` or `ai-env as ambient` declared them. A key reaches a child through its
  environment only, ai-env never writes the deployer's key to a file (it lives in its Strongbox
  entry only), ai-env-ops is refused
  `egress allow` before any AWS call, and every proxy command sends one of the stack's three
  documents, never `AWS-RunShellScript` (S8 operators).
- A remote chat's transcript never reaches the Mac: the remote route runs claude without
  `--session-mirror`, a mirror frame is dropped and counted, and the Mac writes only the view it
  checked and masked. A transcript's presigned URL never reaches an argv, an environment, a log, an
  audit row or the agent: curl in the VM reads it on fd 3 as uid 999 (S9); `egress check`'s own URLs,
  for its `_egress-check` keys only, reach curl's argv in the check's VM (its own, or the `--shell` VM
  `--vm` names), which runs no agent, and are never printed.
- No token enters a git process: `box fetch --smart-http` speaks smart-HTTP with ai-env's own client,
  and the VM's `git http-backend` runs as the agent with an allowlisted CGI environment and no
  receive-pack. The pre-push hook refuses a push of `refs/remotes/*` or `refs/ai-env/*` and fails
  closed without its binary (S9).
- A claude binary reaches a VM only as S3's object under the length and SHA-256 its signed release
  manifest names, once the release signature (the vendored key, gpgv, fail-closed) and the Docker
  tests admitted it; a fresh VM holding no credential puts it there, the Mac never uploads it, and a
  VM runs it only once its size, SHA-256 and version match (S11).
- The panel listens on 127.0.0.1 only, behind a fresh bearer per run that is never written anywhere;
  it checks `Host`, `Origin` and `Sec-Fetch-Site`, sets no cookie, and every action asks its own
  Touch ID (S11).

## Workspace

| crate | role |
|---|---|
| `crates/ai-env-age` | pure-Rust age *header* parser + tag matcher (`#![forbid(unsafe_code)]`, no crypto beyond SHA-256/HKDF-Extract, fuzz-tested, KAT-frozen against real age output; MSRV 1.88) |
| `crates/ai-env-cli` | one library (`ai_env_cli`) and two binaries: `ai-env` (the classic commands, the MicroVM-bridge operator commands behind the `bridge` feature, and the `shim` VM mode behind the `shim` feature) and `ai-env-claude` (the Cursor wrapper; `required-features = ["bridge"]`). Rust 1.94.1+ (the AWS SDK's MSRV); toolchain pinned to 1.98.1 |

Features: `default = ["bridge", "shim"]`. The VM image is built with `--no-default-features
--features shim`, which contains no AWS SDK, no TLS client and no crypto provider (`make
check-features` asserts it). The bridge design and its stages live in `plans/v6-microvm-bridge.md`
(gitignored working documents).

```sh
make help                                         # every target, one line each
make build test                                   # all four feature sets
make doc-test                                     # the README's and SKILL.md's sh doc-test blocks, dry, in a planted HOME (also in make test)
make clippy lint                                  # -D warnings in every cfg world + TLS/WS grep guards
make check-bins check-features check-msrv         # packaging invariants
make vm-build                                     # cargo lambda build --arm64 (shim only) → image/ai-env
make image-zip test-docker                        # the S3 image: stage + scan + zip, then the opt-in Docker tests
make vm-run ARGS='shim --help'                    # run image/ai-env inside the AL2023 arm64 base image
make gates                                        # G1–G8 pre-code gates → plans/gates.md (ops: one Touch ID, none under
                                                  #   ai-env as; G7 simulates ai-env-deployer and ai-env-ops)
cargo test                                        # everything except hardware
AI_ENV_SE_TESTS=1 cargo test -- --ignored         # real enclave round-trips (this Mac only)
```

Cross-building needs cargo-lambda ≥ 1.9.2 (older releases embed a cargo-zigbuild that cannot link
aarch64 on rustc 1.9x) and the `aarch64-unknown-linux-gnu` target on the pinned toolchain
(`rustup target add aarch64-unknown-linux-gnu --toolchain 1.98.1`). `rustfmt` is advisory: the
house style is wider than rustfmt's defaults, so `make fmt` reports but never gates.
