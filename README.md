# ai-env

**Encrypted `.env` files that stay `.env` — unlocked by Touch ID.**

AI coding agents read files. Ignore files don't stop them — Claude Code has been reported
ignoring both `.claudeignore` and `.gitignore`. An ignore file is a suggestion; encryption is a
boundary. `ai-env` encrypts your `.env` **in place**: the file keeps its name, stays a valid
dotenv file, and parses cleanly in every tool that loads it — but the secrets inside are
age-encrypted to a key in your Mac's **Secure Enclave**. Using them requires **Touch ID**.

```sh
brew install age age-plugin-se
cargo install --path crates/ai-env-cli     # no Xcode needed

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
instead, for suspected-compromise restores).

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
ai-env keys    restore NAME [--rekey DIR] [--new-recovery]   # recreate from Strongbox identity
ai-env rekey   [DIR] [--dry-run] [--yes]                  # re-encrypt containers under DIR
ai-env verify-recovery NAME                               # the quarterly drill
ai-env doctor                                             # environment + repo health check
```

Exit codes: `0` ok (broken pipes too) · `1` error · `2` usage · `3` cancelled at the prompt ·
`4` no key opens this file · `5` auth unavailable (plugin missing, no GUI session) · `6` corrupt
or plaintext file where a container was expected.

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
| `crates/ai-env-age` | pure-Rust age *header* parser + tag matcher (`#![forbid(unsafe_code)]`, no crypto beyond SHA-256/HKDF-Extract, fuzz-tested, KAT-frozen against real age output) |
| `crates/ai-env-cli` | the `ai-env` binary |

```sh
cargo test                                        # everything except hardware
AI_ENV_SE_TESTS=1 cargo test -- --ignored         # real enclave round-trips (this Mac only)
```
