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
ai-env infra  pin [--manifest FILE | --check-bundle] [--lock FILE]  # image/claude.lock from a release manifest; lock vs Cursor bundle
ai-env infra  status [--write] [--stack dev] [--cwd infra]          # Pulumi outputs + a live image read → bridge.toml [aws] + state/infra.toml
ai-env infra  base-image [--name al2023-1] [--version 1]  # the pinned managed base image is AVAILABLE
ai-env infra  versions-diff --before F --after F [--record-probe]   # image versions around a deploy (bridge feature)
ai-env creds  aws-set [--user ai-env-runtime] [--check] [--force]   # seal `aws iam create-access-key` JSON from stdin
ai-env vm     images [--managed] | list [--all] | status ID | health ID   # MicroVMs of the ai-env image (bridge feature)
ai-env vm     run [--workspace PATH] [--max-duration S] [--egress internet|vpc] [--shell] [--json] …
ai-env vm     token ID [--port 8080|8082|9418] [--minutes M] [--reveal]   # the value only with --reveal
ai-env vm     suspend ID | resume ID | terminate ID|--all [--yes] | gc [--yes] [--include-orphans AGE]
ai-env vm     shell ID [--auth header|subprotocol]         # experimental: the platform shell (VM started with --shell)
ai-env vm     smoke [--max-duration 900] [--keep] [--json] # run → RUNNING → /health → terminate, with timings
ai-env lab    list | show PROBE | run PROBE [ID] [--log FILE] [--manual VERDICT]   # probes → lab/probes.jsonl
ai-env shim   --claude PATH [--app-port 8080] …           # VM mode: MicroVM image entrypoint (shim feature)
ai-env-claude <realBinary> <claude args…>                 # Cursor's claudeProcessWrapper target (bridge feature)
```

Exit codes: `0` ok (broken pipes too) · `1` error · `2` usage · `3` cancelled at the prompt ·
`4` no key opens this file · `5` auth unavailable (plugin missing, no GUI session, AWS credentials
unavailable) · `6` corrupt or plaintext file where a container was expected · `7` AWS/infra API
failure · `8` MicroVM terminal or transport lost · `9` policy refusal (tripwire, egress gate,
workspace outside the approved roots).

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
  retries once when the child reports `No conversation found with session ID:` (the child is logged
  out unless `CLAUDE_CODE_OAUTH_TOKEN` is set — S7 delivers it);
- writes `logs/wrapper.log`, a second census row with `end`/`exit` (`ai-env wrapper census` shows
  `exit=… dur=…`), `audit.jsonl` rows for retries, and one `state/sessions/<uuid>.toml` per chat
  (`ai-env session list|show|forget`; rows hold digests and a summary, never request bodies);
- exits within 1.5 s of the extension closing stdin (SIGTERM at +0.8 s, SIGKILL at +1.2 s) and
  within 1 s of a SIGTERM.

Debug builds also honour the lab knobs `AI_ENV_BRIDGE_LAB_EXIT=<code>:<msg>:after-init`,
`AI_ENV_BRIDGE_LAB_IGNORE_EOF=1|2`, `AI_ENV_BRIDGE_LAB_STDOUT_NOISE=1` and
`AI_ENV_BRIDGE_LAB_DELAY_INIT_MS=<n>` (compiled out of release builds).

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
and bakes a fresh, reviewed config subset — never the Mac's own `~/.claude`.

`ai-env shim` is the image's ENTRYPOINT. As PID 1 it is a small init (child subreaper, signal
forwarding, orphan reaping) that runs the same binary as its worker; the worker serves the
platform hooks on 9000 (`/ready` waits for the listeners and one `claude --version`, `/validate`
checks the version against the lock, the settings files and that no build-time state leaked into
the snapshot, `/run` is first-wins and fail-closed without a payload), `/health` on 8080 and a
placeholder on 9418. In v0 it logs where hook requests come from and measures the clock without
stepping it (`--hook-source enforce` and `--clock forward` exist for S6).

```sh
make image-zip                 # vm-build + stage + scan + zip
make test-docker               # the shim in the base image (L1) and the built image (L2); stamps the zip
make s3-preflight PHASE=a      # build-side preconditions, one row each
make check-policies preview-scratch   # IAM Access Analyzer + a throwaway-backend Pulumi preview (read-only)
make deploy                    # (Mike) Pulumi up of infra/ in eu-central-1, then waits for the image build
make infra-status WRITE=1      # stack outputs (+ the image's live state) → bridge.toml [aws] (comments kept) + state/infra.toml
make runtime-key               # seal a key of the ai-env-runtime user under the bridge keystore key
```

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
  `vm smoke` and `lab run` imply it because no credential ever enters those VMs.
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
