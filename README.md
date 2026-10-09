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
ai-env doctor [--json]                                    # environment + repo health check (exit 1 on any [NO ] row)
ai-env gates  [--json] [--only G1,G3] [--out FILE]        # MicroVM bridge pre-code gates → plans/gates.md (bridge feature);
                                                          #   --only re-measures a subset: nothing is written, go/no-go is not evaluated
ai-env wrapper install [--write] [--permission-mode M]    # point Cursor's claudeProcessWrapper at the sibling ai-env-claude
                                                          #   (dry run unless --write; backs up settings.json; bridge feature)
ai-env wrapper census [--last N] [--json] [--record-probes]  # invocation shapes the wrapper recorded (bridge feature)
ai-env session list [--json] | show UUID [--json] | forget UUID   # sessions the S2 pump registered (bridge feature)
ai-env infra  scan DIR [--profile image|repo] [--json]    # secrets + unsafe-settings scan of an image tree; exit 9 on a finding
ai-env infra  pin [--manifest FILE | --check-bundle | --bundle-version] [--lock FILE]  # image/claude.lock from a release manifest; lock vs Cursor bundle; the bundle's version
ai-env infra  status [--write] [--stack dev] [--cwd infra]          # Pulumi outputs + a live image read → bridge.toml [aws] + state/infra.toml
ai-env infra  base-image [--name al2023-1] [--version 1]  # the pinned managed base image is AVAILABLE
ai-env infra  versions-diff --before F --after F [--record-probe]   # image versions around a deploy (bridge feature)
ai-env creds  aws-set [--user ai-env-runtime] [--check] [--force]   # seal `aws iam create-access-key` JSON from stdin
ai-env creds  setup-token [--stdin|--from-env] [--no-combined] [--force]   # seal the Claude setup-token (asked for hidden) (S7)
ai-env creds  status [--json] [--unseal] | forget [--yes]  # what is sealed, without Touch ID / delete the token and its copies
ai-env vm     images [--managed] | list [--all] | status ID | health ID   # MicroVMs of the ai-env image (bridge feature)
ai-env vm     run [--workspace PATH] [--max-duration S] [--egress internet|vpc] [--shell] [--json] …
ai-env vm     token ID [--port 8080|8082|9418] [--minutes M] [--reveal]   # the value only with --reveal
ai-env vm     suspend ID | resume ID | terminate ID|--all [--yes] | gc [--yes] [--include-orphans AGE]
ai-env vm     shell ID [--auth header|subprotocol]         # experimental: the platform shell (VM started with --shell)
ai-env vm     smoke [--max-duration 900] [--keep] [--exec [--with-credential]] [--json]   # run → RUNNING → /health (→ exec checks → a credentialed claude -p) → terminate, with timings
ai-env vm     exec ID [--cwd P] [--env K=V]… [--detach-grace S] [--with-credential | --credential-file P] [--deliver fd|env] -- CMD ARGS…   # run as the agent over /agent; stdio byte-exact, the command's exit status (S6; the credential S7)
ai-env vm     warm WORKSPACE [--json]                      # deliver the sealed setup-token to the workspace's VM ahead of time (S7)
ai-env vm     attach ID --spawn UUID [--from-seq N]       # reattach to a running command (the newest client wins)
ai-env vm     health ID --detail [--json]                  # /health/detail with the session bearer: guard, sockets, spawns, listeners
ai-env lab    list | show PROBE | run PROBE [ID] [--log FILE] [--manual VERDICT]   # probes → lab/probes.jsonl
ai-env egress status [--json] | env [--shell] | reload [--if-changed]   # S5 operator commands (the operator's aws CLI; bridge feature)
ai-env egress allow SLUG HOST [--remove] | suspend HOST [--restore]    # per-workspace extras (global on the proxy) / the kill switch
ai-env egress check [--vm ID] [--keep] [--json] [--if-needed]          # from a vpc VM: direct egress and DNS closed, the allowlist working → state/egress-verified.toml
ai-env proxy  stop [--yes] | start | patch                             # the squid instance (stopped: no vpc VM has egress)
ai-env shim   --claude PATH [--app-port 8080] …           # VM mode: MicroVM image entrypoint (shim feature)
ai-env-claude <realBinary> <claude args…>                 # Cursor's claudeProcessWrapper target (bridge feature)
```

Exit codes: `0` ok (broken pipes too) · `1` error · `2` usage · `3` cancelled at the prompt (or a
Ctrl-C during `lab run`, once the probe's VMs are ended) · `4` no key opens this file · `5` auth
unavailable (plugin missing, no GUI session, AWS credentials unavailable) · `6` corrupt or plaintext
file where a container was expected · `7` AWS/infra API failure · `8` MicroVM terminal or transport
lost · `9` policy refusal (tripwire, egress gate, workspace outside the approved roots). `vm exec`
exits with the remote command's own status (128 + N when a signal killed it; 127 when the VM has no
such program, 126 when it cannot run it and 1 when the working directory cannot be made, each with an
`ai-env: vm exec:` line); its own failures keep 7/8/9 (with a credential also 3, 4 and 5: see
Credentials) and print an `ai-env:` line (9 also when the VM already runs 8 commands), and a
credentialed `claude` whose delivered token Anthropic refuses ends with 5 and such a line instead of
its own status. No stop signal after the refusal changes that 5. The line is the last write to
stderr: a signal that cuts the last output short leaves it a second more, and a stderr nobody reads
gets none. After SIGTERM or SIGHUP it exits 143, after a Ctrl-C before the command started (or a
second one while the connection is down) 130, and after a closed stdout 0, whatever the command did.

`ai-env doctor` exits `1` when any row is `[NO ]` and `5` when AWS credentials are unavailable;
every row is printed first. Rows marked `[-  ]` (not configured yet) and `[!! ]` (warnings) never
change the exit code.

### The Cursor wrapper (stages S1–S2)

`ai-env wrapper install --write` writes two user settings, `claudeCode.claudeProcessWrapper`
(the absolute path of the `ai-env-claude` next to `ai-env`) and `claudeCode.initialPermissionMode`
(default `default`, i.e. the mode Cursor labels Manual; with a wrapper configured the extension
always passes `--permission-mode` explicitly). It backs up `settings.json` first, keeps comments
and key order, and prints the exact snippet when it cannot write. Reload the window afterwards.
Every invocation the wrapper handles — chat sessions, config probes, `auth status --json`,
`plugin list --json`, `mcp add` … — execs the bundled binary locally and appends one redacted
JSON line to `~/.config/ai-env/bridge/logs/census.jsonl` (environment variable NAMES, a short
allowlist of non-secret values, argv with MCP credentials and the positional tail after `--`
masked). `ai-env wrapper census` prints it; `--record-probes` writes the `entrypoint` and
`stock-ext-oauth` verdicts to `lab/probes.jsonl`. `AI_ENV_BRIDGE_LOCAL=1` in the extension's
environment is the kill switch: exec the real binary, no census, no bridge.

With `AI_ENV_BRIDGE_MODE=local-child` (or `local-scratch`) in `claudeCode.environmentVariables`,
a stream-json chat session is no longer exec'd: the wrapper spawns the bundled binary as a piped
child with `--session-mirror` appended and stands between it and the extension (stage S2, no AWS).
Everything else — every subcommand, `--version`, and every session while the variable is unset —
still execs exactly as above. The pump:

- peels the child's `transcript_mirror` frames (never forwarded) and, when
  `AI_ENV_BRIDGE_MIRROR_ROOT` is set or the child uses another config dir, appends their entries
  byte-for-byte under the same relative path (0600 files, 0700 directories, no symlinks);
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
`AI_ENV_BRIDGE_LAB_DELAY_INIT_MS=<n>`, and from S7 `AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS=<n>` (once the
session is initialized the pump sends the extension one `oauth_token_refresh` request of its own,
waits at most n ms, never forwards the answer, and records its class in the end row as
`synthetic_oauth:<class>`, which `ai-env wrapper census --record-probes` puts in the
`stock-ext-oauth` row's note) and `AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS=<n>` (the `local-scratch`
unseal's budget in ms, in place of `[creds].unseal_timeout_s`; the same knob budgets a credentialed
`vm` or `lab` command's unseals: see Credentials). All are compiled out of release builds, and the
live make targets also drop the two S7 knobs.

### The MicroVM image and its infrastructure (stage S3)

`image/` holds everything the MicroVM image is built from, and `image/MANIFEST` lists it:
`make image-zip` cross-builds the shim (`make vm-build`), copies exactly the listed files into
`target/image/stage` with the listed modes (an unlisted file stops the build), scans the staged tree
with `ai-env infra scan` (built-in tripwires for API keys, private keys, age identities, JWTs and
URL credentials, plus rules for the baked Claude settings: no `bypassPermissions`, no broad allow
entries, no secret-named `env` keys; exit 9 names file, line and rule, never the matched text), and
writes a deterministic zip plus `target/image/image.json` (its sha256 and S3 key). The image pins
Claude Code by version, size and SHA-256 (`image/claude.lock`; `make claude-pin CLAUDE_VERSION=<v>`
refreshes it from the release manifest, verifying its signature when the release key is in gpg)
and bakes a fresh, reviewed config subset — never the Mac's own `~/.claude`. The image carries the
version the Mac's Cursor extension bundles (the deploy's preflight P10 refuses any other), and the
extension updates itself, often daily: `make claude-update` follows it in one command.

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
make s3-preflight PHASE=a      # build-side preconditions, one row each
make check-policies preview-scratch   # IAM Access Analyzer + a throwaway-backend Pulumi preview (read-only)
make deploy                    # (Mike) Pulumi up of infra/ in eu-central-1, then waits for the image build
make infra-status WRITE=1      # stack outputs (+ the image's live state) → bridge.toml [aws] (comments kept) + state/infra.toml
make runtime-key               # seal a key of the ai-env-runtime user under the bridge keystore key
make claude-update             # (Mike, at a terminal) follow the Cursor extension's Claude Code: claude-pin, test-docker,
                               #   deploy, infra-status WRITE=1, proxy-start, egress check --if-needed (only what is
                               #   not current; rerun resumes)
```

`make claude-update` reads the version of the installed Cursor bundle (`ai-env infra pin
--bundle-version`: a real directory Cursor has not marked obsolete), the lock and the deployed
image's (the stack output `claudeVersion`), and shows the release site's `latest` for comparison
only (and says when the bundle is behind it, ahead of it, or older than the deployed version). When
all three agree it runs `make infra-status WRITE=1`, checks that new VMs start the deployed image
version (a rollback with `make image-deactivate`/`image-activate` stops it, and so does an
`[aws].image_version` that pins another version or is written in a form the script does not read)
and runs `ai-env egress check --if-needed`, which starts no VM once the version new VMs run has a
pass bound to its build and to the connector's live facts. Otherwise
it checks the preconditions first (not under `make -i`/`-k`, a terminal, the Pulumi passphrase in
the environment, Docker and the AWS identity answering), then pins, runs `make test-docker` (unless
it already passed for the current zip), `make deploy` (the plan gate, then Pulumi's own
confirmation), `make infra-status WRITE=1`, the same active-version check, `make proxy-start` (the
check needs squid serving) and the egress check for the new image version (one Touch ID). The first
failure stops it naming the step; running it again resumes (once it has started a deploy, a marker
in `target/image` makes the rerun finish every remaining step, `make proxy-start` included). Near
the image-version quota it lists old versions to deactivate, never one a VM still runs. It cannot
run unattended (Pulumi's confirmation and the Touch ID are the point); Cursor updates the extension
on its own unless its Auto Update is off. The new `image/claude.lock` is left for review and commit.

Pulumi state stays in the operator's local backend; `infra/Pulumi.dev.yaml` and
`infra/config/dev.env` (budget email and limit) are not committed — copy the `.example` files. No
secret ever enters Pulumi config, outputs or state: the runtime user's access key is created by
`make runtime-key`, piped straight into `ai-env creds aws-set` and sealed to
`~/.config/ai-env/bridge/credentials/aws.env`.

### MicroVM lifecycle (stage S4)

`ai-env vm` starts, inspects and stops MicroVMs of the image S3 deployed. Every command that talks
to AWS unseals the runtime principal's key from `credentials/aws.env` in-process (one Touch ID per
command; `[aws] credentials = "profile:<name>"` reads that one profile instead) and never hands it
to a child process. The region, the control-plane URL and the TLS policy (TLS 1.3 to the MicroVM
endpoint, Amazon Root CA 1–4 only, proxy variables ignored) are pinned in code; `AWS_REGION`,
`AWS_ENDPOINT_URL*`, `AWS_PROFILE` and `~/.aws/config` cannot move them.

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
`cloudtrail-payload ID` asks AWS as the operator's own `aws` identity (within 7 days of the VM's end, while
its row exists): RunMicrovm is a CloudTrail data event (resource type `AWS::Lambda::MicrovmImage`, off by
default, never in event history). It checks the trails and the CloudTrail service-linked channels of
eu-central-1 — CloudWatch's CloudTrail ingestion runs through one, as does Security Lake. A trail or
CloudWatch channel that takes RunMicrovm → the probe prints how to fetch the record (the trail's S3 log
file, or an `aws logs filter-log-events … --unmask` command per log group) and reads it with `--log FILE`
(raw or OCSF CloudWatch records; a CloudWatch copy may be transformed, the row notes where it came from);
another service's channel → read it there and record with `--manual`; nothing → it prints the
`--manual not-logged` command to run once you have confirmed what it cannot see (CloudTrail Lake event
data stores, channels homed in other Regions, organization-level CloudWatch or Security Lake). It never
records a verdict for what it could not see. The identity needs `cloudtrail:DescribeTrails`,
`GetEventSelectors`, `ListChannels`, `GetChannel`, `logs:DescribeLogGroups`, and for the printed command
`logs:FilterLogEvents` and `logs:Unmask`.

```sh
make test-aws-readonly         # part A: TLS to the MicroVM proxy, managed images, ListMicrovms, GetMicrovm (read-only)
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
- **Operator commands** (`ai-env egress …`, `ai-env proxy …`) are the operator's own `aws` CLI calls
  (region and endpoint pinned; the account must be the connector's), reading the stack's ids from
  `state/infra.toml`: `egress allow SLUG HOST [--remove]`, `egress suspend HOST [--restore]` (a concurrent
  write is detected after the fact from the parameter's version, never prevented; any failure after a
  removal says `STILL ALLOWED on the proxy` and exits 7; an AWS service host (`amazonaws.com`,
  `amazonaws.com.cn`, the `.aws` domain) is refused with exit 9, and one already listed shows as drift in
  `egress status`: a VM reads its execution role's keys from IMDS, and those keys work at AWS endpoints
  and nowhere else), `egress reload [--if-changed]`, `egress status` (connector, ENIs, routes, security groups,
  NACL, VPC DNS and DHCP, no endpoints, NAT, peering or IPv6, the proxy serving exactly the parameters
  the stack rendered; any drift is exit 1), `egress env`, `proxy stop|start|patch`.
- **`egress check`** starts its own `--egress vpc --shell` VM and runs, through the platform shell,
  curl and dig cases: direct egress and DNS must be closed, the allowlist must answer (401 from the API)
  and refuse the rest. The case markers are VM-reported, so a pass also needs the VM-independent
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
  rule, and whose DNS verdicts (the check's and the newest `dns-path`) are `no-dns` or `platform-dns:<ip>`
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
make test-proxy                # squid on AL2023 in Docker: the allowlist, rebinding, reload, rollback (+ real systemd)
make preview-scratch [EGRESS_MODE=firewall] [NEGATIVE=…]   # read-only Pulumi preview + the plan check and its negatives
make deploy                    # (Mike) plan check + replacement guard, pulumi up, connector-wait, proxy reload, egress status
                               # (its preview runs --non-interactive: export PULUMI_CONFIG_PASSPHRASE_FILE for a passphrase stack)
make infra-status WRITE=1      # adds egress_connector_arn and proxy_private_ip to bridge.toml [aws]
make s5-smoke                  # three `vm smoke --egress vpc --json` passes; the echo must be exactly the connector
make test-egress               # the live egress tests (direct closed, allowlist, extra + removal, after resume); a skipped proof fails it
make connector-probe CONFIRM=create-probe-connector   # a throw-away connector: RunMicrovm while PENDING, the activation time (~4.5 min), deleted on every path
ai-env egress check            # the recorded proof the credential gate needs (re-run after every new image version; --if-needed: none when the version new VMs run has it)
make egress-logs [FOLLOW=1]    # squid's access log (hosts only, never a path)
make proxy-stop                # when idle: stops the proxy (no vpc VM has egress then); proxy-start brings it back
```

`ai-env doctor` shows `[NO ]` for the egress row while `[egress] require = true` (the default) and no
connector is configured; a stopped proxy is `[-  ]`, never `[NO ]`. Its DNS row says whether the newest
`dns-path` verdict is accepted, and shows the exact `accept_platform_dns = "<ip>"` line to write when the
value names no resolver.

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
  it — it never resumes one itself — before exit 8 naming `vm resume` and `vm attach`).
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
login: an inference-only OAuth token, valid for a year) into `credentials/setup-token.env`, an ai-env
container sealed to `[creds].key` like the runtime key. It asks for the token hidden on the terminal
(`--stdin` takes exactly one line from a pipe and refuses a terminal; `--from-env` reads
`CLAUDE_CODE_OAUTH_TOKEN`); an API key (`sk-ant-api…`) is refused. What is recorded about the token, in
the container's metadata line and the audit row, is its kind prefix (`sk-ant-oat01-`), its length and
when it was sealed, never more. Clear the terminal's scrollback and the clipboard afterwards (after
`--stdin` also any file or shell history line that held it; after `--from-env`, unset the variable
instead): the command reminds you.

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
  which case holds, without a prompt.
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
  output format, a line that starts with claude's 401 message (or an error result saying it),
  followed by exit 1, counts too; that command has ended by itself, and nothing is stopped. Either way
  `vm exec` exits 5 with an `ai-env:` line saying what it saw, written last on stderr (a later
  SIGTERM, SIGHUP or Ctrl-C keeps the 5; a SIGTERM or SIGHUP during the stop, or any of the three
  during the check, leaves the last output at most 3 s, as a stop does; a stderr nobody reads gets no
  line), audits `credential_rejected`, and never starts the command again; `vm smoke --with-credential`
  records a refused `claude -p` the same way. The rejection is recorded against the sealed container:
  credentialed commands then refuse at once (exit 5, no Touch ID) until `creds setup-token` seals a new
  token. That record is `state/creds.toml`: one that cannot be read refuses them too (exit 5, naming
  it, since which tokens were refused is then unknown), the wrapper's `local-scratch` child then runs
  logged out, and `creds status` and doctor show it as a warning. A refused `--credential-file`
  container with a seal of its own blocks only itself; the sealed setup-token is not affected. A byte
  copy of `setup-token.env` has the sealed token's seal, so its refusal is the sealed token's.
- **Forgetting.** `creds forget` lists, then with `--yes` deletes, `setup-token.env`, `combined.env` and
  their backups; `aws.env` stays. It cannot revoke the token: revoke it on Anthropic's side (which page
  does it is not recorded here yet: Mike fills it in from part B), in the Anthropic account that
  created it. Terminate the VMs it names.
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
                                #   a recorded refusal, the VMs that may hold the token: no Touch ID
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
plaintext buffer), `Ctrl+Q` quits.

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
make clippy lint                                  # -D warnings in every cfg world + TLS/WS grep guards
make check-bins check-features check-msrv         # packaging invariants
make vm-build                                     # cargo lambda build --arm64 (shim only) → image/ai-env
make image-zip test-docker                        # the S3 image: stage + scan + zip, then the opt-in Docker tests
make vm-run ARGS='shim --help'                    # run image/ai-env inside the AL2023 arm64 base image
make gates                                        # G1–G8 pre-code gates → plans/gates.md
cargo test                                        # everything except hardware
AI_ENV_SE_TESTS=1 cargo test -- --ignored         # real enclave round-trips (this Mac only)
```

Cross-building needs cargo-lambda ≥ 1.9.2 (older releases embed a cargo-zigbuild that cannot link
aarch64 on rustc 1.9x) and the `aarch64-unknown-linux-gnu` target on the pinned toolchain
(`rustup target add aarch64-unknown-linux-gnu --toolchain 1.98.1`). `rustfmt` is advisory: the
house style is wider than rustfmt's defaults, so `make fmt` reports but never gates.
