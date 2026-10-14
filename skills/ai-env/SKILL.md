---
name: ai-env
description: Work with ai-env encrypted .env files and ai-env MicroVM sessions — read this when a .env file contains AI_ENV=1 and AI_ENV_DATA, when the user mentions ai-env, when an app's env config appears to be ciphertext, or when a Cursor chat runs in an ai-env MicroVM (/proc/1/comm is ai-env).
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
in a disposable AWS MicroVM, not on the Mac. The Mac keeps the editor, the chat's transcript
and the git history; the VM has a copy of the checkout to work in.

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
ai-env vm list                     # the VMs that run or are suspended
```

Review with git (`git log --oneline BRANCH..box/BRANCH`) and merge by hand; never push a
`box/*` ref. `ai-env vm terminate ID` ends a VM (the next chat seeds a fresh one).
`AI_ENV_BRIDGE_LOCAL=1` in Cursor's `claudeCode.environmentVariables` runs every chat on the
Mac again.

**Exits Cursor shows** as `Claude Code process exited with code N`, the last stderr line
(`ai-env-claude: …`) naming the fix: `3` the Touch ID dialog was dismissed (nothing started;
reopen the chat) · `5` no Touch ID in time, no sealed setup-token, or Anthropic refused it
(`ai-env creds status`) · `7` AWS, or a VM image older than remote sessions (`make deploy`) · `8`
the VM is gone or unreachable (reopen the chat from the picker) · `9` a policy refusal: a
secret or a widening setting in what the seed would carry (`ai-env box seed` lists the
findings), a workspace that is not a git repository, or too many VMs (`ai-env vm list`).
