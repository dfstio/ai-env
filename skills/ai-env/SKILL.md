---
name: ai-env
description: Work with ai-env encrypted .env files, ai-env MicroVM sessions and ai-env's AWS side — read this when a .env file contains AI_ENV=1 and AI_ENV_DATA, when the user mentions ai-env, when an app's env config appears to be ciphertext, when a Cursor chat runs in an ai-env MicroVM (/proc/1/comm is ai-env), or before a make target, aws call or ai-env command reaches ai-env's AWS account (make deploy, ai-env as, ai-env egress).
---

# ai-env — encrypted .env files

A `.env` file containing the line `AI_ENV=1` plus an `AI_ENV_DATA=` value is an **ai-env
container**: the real variables are age-encrypted to a Secure Enclave key on this Mac and can
only be used after the **user** approves a Touch ID prompt.

## What you (an AI agent) should do

- **Do not** try to base64-decode or brute-force `AI_ENV_DATA` — it is age ciphertext; there
  is nothing to extract without the hardware key.
- **Do not** delete, rewrite, truncate, or "fix" the file — every byte of `AI_ENV_DATA`
  matters, and the plaintext may exist nowhere else.
- **Do not** commit a plaintext `.env` over an encrypted one.
- To *run* something that needs the variables, use (the user will confirm via Touch ID):
  ```sh
  ai-env run -- <command> [args...]        # variables injected into the child env only
  ai-env run -f path/to/.env -- <command>
  ```
- To *see* the variables (requires the user at the machine): `ai-env show`
- To learn about a file without any prompt: `ai-env info` / `ai-env which` / `ai-env doctor`
- If a build fails because config vars are missing and the env contains `AI_ENV=1`: the app
  loaded the encrypted file directly. The fix is `ai-env run -- <the command>`, not editing
  the file.

## Editing the variables

Preferred (plaintext never touches disk; user gets a secure in-terminal form):
```sh
ai-env edit                 # user Touch ID; interactive — the USER must drive it, not you
```
`edit` is interactive and refuses non-TTY stdin, so run it in the user's terminal or ask the
user to run it. Fallback (leaves plaintext on disk between the two steps):
```sh
ai-env decrypt --force      # restore plaintext in place (user Touch ID)
# ... edit .env ...
ai-env encrypt              # re-encrypt in place (no prompt)
```

Remind the user to re-encrypt if a plaintext `.env` is left behind (`ai-env doctor` flags it).

## Exit codes you may see

`3` user cancelled the Touch ID prompt · `4` no local key opens this file (recovery identity
needed) · `5` age/age-plugin-se missing or no GUI session (e.g. over SSH) · `6` the file is
corrupt or is plaintext where a container was expected.

On exit `4`: if the user has the recovery identity in their password manager, suggest
`ai-env keys restore NAME --rekey .` — it is interactive (the USER pastes the identity into
their terminal; do not handle the secret yourself) and restores normal Touch ID access.
It works whether or not the key still exists: a missing key is recreated; an existing key
enters sweep-only mode (paste verified against the stored recovery recipient, files
re-encrypted, no new key).

To grant a server or teammate decrypt access, use
`ai-env keys add-recipient NAME age1… [--label TEXT] [--rekey DIR]` with their PUBLIC
recipient only — never an `AGE-SECRET-KEY` private identity (the CLI refuses it).

## MicroVM sessions (ai-env bridge)

In the bridge's remote mode a Cursor chat whose workspace is under the configured roots runs
in a disposable AWS MicroVM, not on the Mac. The Mac keeps the editor and the git history; the
VM has a copy of the checkout to work in. The chat's transcript stays in the VM and in S3: the
Mac holds only a view of its last 10 messages, which Cursor's history lists and reopens.

**Signs you are in the VM:** `cat /proc/1/comm` prints `ai-env`, `id -u` prints `1000`, the
checkout sits at the same path as on the Mac (under `/Users/mike`), and `git remote` prints
nothing. Its `~/.claude/CLAUDE.md` holds the rules, in short:

- the developer's uncommitted changes were carried over uncommitted: keep them;
- commit your own work to the current branch in small steps; after every turn the Mac fetches
  it into `refs/remotes/box/*` (the clone is shallow and has no `origin`: nothing is pushed);
- the editor shows the Mac's copy of each file until the developer merges: name the files you
  changed;
- no IDE tools, no package installs (the network reaches the Anthropic API and crates.io),
  and never a credential on disk, in a commit or in a command line.

**On the Mac**, these show and bring back what a VM did (each `ai-env` command that reaches
AWS asks for one Touch ID):

```sh doc-test
ai-env session list                # the chats the wrapper ran (session show UUID names a chat's VM)
ai-env box fetch WORKSPACE --wip   # the VM's commits and uncommitted files into refs/remotes/box/*
ai-env box review BRANCH           # what a push of BRANCH would carry (no AWS, no Touch ID; exit 9 on a finding)
ai-env vm list                     # the VMs that run or are suspended
```

Review with git (`git log --oneline BRANCH..box/BRANCH`) and merge by hand; never push a
`box/*` or `box-quarantine/*` ref. `ai-env vm terminate ID` ends a VM (the next chat seeds a
fresh one). `AI_ENV_BRIDGE_LOCAL=1` in Cursor's `claudeCode.environmentVariables` runs every
chat on the Mac again. `ai-env wrapper status` is read-only (no AWS, no Touch ID) and shows
whether Cursor's wrapper is set and where the chats Cursor starts next will run (it cannot see a
chat already running). `ai-env wrapper uninstall` and `ai-env wrapper install`
change where every later Cursor chat runs: they are the user's to run, never yours.

**Before a push**, `ai-env box review BRANCH` checks what it would carry (the tripwires, the
settings policy, the dotenv rule, the Cargo.lock rules, the pre-push hook's own path): read-only,
so you may run it; exit 9 names each finding's file, line and rule, never the value. A checkout
with the pre-push hook reviews every push itself. Never bypass it (`git push --no-verify`, a push
from another clone, `core.hooksPath` pointed elsewhere), and never edit, remove, chain or commit
the hook; on a finding, tell the user what the review found and let them decide.
`ai-env box hook-install` writes into the user's repository: it is the user's to run (`--dry-run`
only shows the hook).

**Transcripts.** A remote chat's file under `~/.claude/projects/` is a view (its first line starts
with `{"aiEnvView":1,`), not the chat: never edit, move or delete it, and never resume it on the
Mac. `claude -c` or `claude --resume` in a terminal would load the view as if it were the whole
chat (the wrapper refuses that, exit 9, but a terminal's claude never passes through it), and so
would a Cursor reload with the wrapper off while such a chat's tab is open. `ai-env session stage`,
`session sync`, `session gc --remote --yes`, `session migrate-s9 --yes` and
`session forget UUID --purge` move or delete transcripts in S3 and ask for Touch IDs: they are the
user's to run, never yours (without `--yes`, `session gc --remote` and `session migrate-s9` only
list, with no AWS call).

**Exits Cursor shows** as `Claude Code process exited with code N`, the last stderr line
(`ai-env-claude: …`) naming the fix: `3` the Touch ID dialog was dismissed (nothing started;
reopen the chat) · `5` no Touch ID in time, no sealed setup-token, or Anthropic refused it
(`ai-env creds status`) · `7` AWS, or a VM image older than S9's remote sessions (the line names
what it lacks; `make deploy`, which asks the user for the deployer's key) · `8` the VM is gone
or unreachable (reopen the chat from the picker) · `9` a policy refusal: a secret or a widening
setting in what the seed would carry (`ai-env box seed` lists the findings), a workspace that is
not a git repository, too many VMs (`ai-env vm list`), the credential gate
(`refused before any Touch ID: no credential for a vpc VM …`: the user runs the
`ai-env egress check` (or `ai-env lab run dns-path`) the line names; since S9 a pass from
before the check's S3 cases does not count), a chat transcript over the 64 MiB a reopen
carries or pulls inline (the user runs the commands the line names in a terminal:
`ai-env session stage UUID --warm`, which restores the chat into its workspace's VM, after
`ai-env session migrate-s9 --yes` for a chat from before S9, and with `[vm] reuse_per_workspace`
set back to true when the line says it is off), or a local resume of a remote chat's view.

## Deploying and operating the AWS side

Three IAM users run the bridge's AWS account (README, "Identities"): `ai-env-deployer` deploys
and issues keys (its key lives only in the user's Strongbox and is pasted per command),
`ai-env-ops` runs the daily operator commands (the egress and proxy commands but
`ai-env egress allow`, which is the deployer's, `make infra-status`, `make gates`, the logs; its key
is sealed in the bridge's `credentials/ops.env` and opened by Touch ID), and `ai-env-runtime` starts
the VMs and sessions (`credentials/aws.env`, Touch ID).

- **Never** read, print, store or paste an AWS key, and never read the bridge's
  `credentials/*.env` or anything under `~/.aws`. Never run `ai-env creds deployer-key`,
  `ai-env creds aws-set` or `ai-env creds aws-verify` for the user's keys, and never copy an `id`
  or `arn` line, or the key id in a printed `aws iam delete-access-key` command, into notes or plans.
- Never read `~/.config/ai-env/pulumi.env`, the stack's sealed Pulumi passphrase, nor unseal it
  (`ai-env run -f` of it, `ai-env show` or `ai-env edit`): the deploy targets unseal it themselves,
  with the user's Touch ID, in the user's terminal. Never put a passphrase on a command line or in
  a file.
- Never start a deployer-tier target (`make deploy`, `make preview`, `make runtime-key`,
  `make ops-key`, `make deployer-key`, `make image-activate`, …), `ai-env as deployer …`,
  `ai-env egress allow` or `make claude-update` yourself: give the user the exact command to run in a
  terminal of their own, and wait for its result. The deployer's key is pasted at a no-echo prompt on
  `/dev/tty` only: from a shell without a terminal the command stops there with
  `as deployer: no terminal to paste the key into …` (the runner's exit 5); started from your shell,
  the paste would put the key into a process tree you control, and in a terminal you share it could
  land in your own input. Never type, pipe or paste anything into it. `ai-env egress allow` widens
  what every VM may reach: it is the user's call.
- An ops command (`ai-env egress status`, `ai-env proxy start`, `make infra-status`, `make gates`,
  `make logs`, …) asks the user for one Touch ID; under `ai-env as` it asks for none.
- In the user's shell a bare `aws` call finds no credentials of the stack's account, by design (it
  fails, or answers as another account's default profile), and ai-env never falls back to the
  shell's own AWS settings. For a read, run `ai-env as ops -- aws …` (the user answers one Touch
  ID); never point `AWS_PROFILE` or `~/.aws` somewhere else to get around it. ai-env needs the
  account root's key only for the bootstrap and break-glass, the user's decisions, which load it
  into a terminal of their own, closed afterwards (README "Break-glass"). Otherwise never suggest
  loading it into a terminal used for ai-env (the runners ignore it, but a plain `aws` call there
  would run as the root).
- `make -n TARGET` shows what a target would run and asks for nothing.
- On `AccessDenied`, report the action and the resource the error names, and stop: never retry
  with other credentials. A missing right is a change to `infra/policies.ts` that the user deploys
  (`make deploy-policies`), and break-glass (the account root, `BREAKGLASS=1`) is the user's
  decision alone.
- Your own read-only checks in another account, on your session's own credentials:
  `make check-policies` and `make preview-scratch` run on them as they are; an `ai-env` operator
  command, and `make s3-preflight PHASE=a` and `make check-base-image` (both run
  `ai-env infra base-image`), need `ai-env as ambient -- …` (refused when those credentials are the
  account root's; never use it with credentials of the stack's own account). Their output may name
  the account: keep it on the terminal, and mask it (`sed -E 's/[0-9]{12}/ACCOUNT/'`) before it goes
  into a file.
