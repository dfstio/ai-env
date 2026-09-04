---
name: ai-env
description: Work with ai-env encrypted .env files — read this when a .env file contains AI_ENV=1 and AI_ENV_DATA, when the user mentions ai-env, or when an app's env config appears to be ciphertext.
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
