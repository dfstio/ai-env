# certs/

Public material the binaries embed. Nothing here is secret.

- `AmazonRootCA1.pem` to `AmazonRootCA4.pem`: the Amazon Trust Services roots of the Mac's one TLS policy (S6, `src/bridge/tls.rs`).
- `claude-code-release.asc` and `claude-code-release.gpg`: the Claude Code release signing key (S11 part A, below).

## The Claude Code release key (S11)

Every Claude Code version a VM may run is admitted first (`ai-env claude admit`, plan D2). Its release manifest (`manifest.json`) must carry a good signature by this key, checked with `gpgv` against this key alone, fail-closed. The Linux binaries have no code signature of their own, so the manifest's signature is their only anchor. `src/bridge/claude/release.rs` embeds `claude-code-release.gpg` with `include_bytes!`.

### Provenance

| Item | Value |
|---|---|
| Source | `https://downloads.claude.ai/keys/claude-code.asc` |
| Vendored | 23 Oct 2026, by the lead, as S11 phase 0's first piece (`plans/s11-plan.md`, part A log) |
| Fetched with | `/usr/bin/curl -q --proto '=https' --tlsv1.2`, into a throwaway GnuPG home (no personal keyring touched) |
| Key | RSA 4096, created 2026-03-30, long key id `BAA929FF1A7ECACE`, no subkeys |
| User id | `Anthropic Claude Code Release Signing` |
| Primary fingerprint | `31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE` |

`gpg --show-keys --with-colons claude-code-release.asc` prints, for its fingerprint:

```text
fpr:::::::::31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE:
```

That fingerprint is `wire::pin::RELEASE_KEY_FPR` and the Makefile's `CLAUDE_GPG_FPR` (Makefile:83). A test ties the three together without running gpg.

### The two files

| File | What | sha256 |
|---|---|---|
| `claude-code-release.asc` | the key as published (ASCII armor) | `bd70a5e4a268002704024ceba7f8446024114e94f3f0bdd11c23a9e592be81c6` |
| `claude-code-release.gpg` | `gpg --dearmor` of it: the binary keyring `gpgv --keyring` takes | `0e122272125dd4bed96be0034cd95c84e9db07b4cf9bcddbe7c3ae01f3580646` |

### Verified on 23 Oct 2026

`gpgv --status-fd 1` against this key alone verified two releases' `manifest.json.sig`. Each gave a GOODSIG and a VALIDSIG whose last field is the pinned primary fingerprint (the part A log records these two lines; the fields elided here were not recorded):

```text
2.1.308 (signed 22 Oct):
[GNUPG:] GOODSIG BAA929FF1A7ECACE Anthropic Claude Code Release Signing …
[GNUPG:] VALIDSIG 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE 2026-10-22 … 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
2.1.305 (signed 20 Oct):
[GNUPG:] GOODSIG BAA929FF1A7ECACE Anthropic Claude Code Release Signing …
[GNUPG:] VALIDSIG 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE 2026-10-20 … 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
```

What the two manifests said for linux-arm64: 2.1.308 `fdd22e6c…`, 292 085 944 bytes; 2.1.305 `5265a602…`, 290 447 544 bytes, equal to `image/claude.lock` (the image's claude is the signed release).

### Re-vendoring after a rotation

If Anthropic rotates the key, every admission fails closed (`ai-env claude admit` names the signature), and chats keep the newest admitted version or the image's claude until the new key is vendored. To vendor it:

1. Fetch the published key into a throwaway GnuPG home, never a personal keyring. In zsh, quote `'=https'`: unquoted, `=https` is zsh's equals expansion.

   ```sh
   d=$(mktemp -d) && chmod 700 "$d"
   /usr/bin/curl -q --proto '=https' --tlsv1.2 -fsSL -o "$d/claude-code.asc" https://downloads.claude.ai/keys/claude-code.asc
   gpg --homedir "$d" --show-keys --with-colons "$d/claude-code.asc"
   ```

2. Check the new `fpr` line against Anthropic's published fingerprint (code.claude.com/docs/en/setup), out of band.
3. Write both files: `cp "$d/claude-code.asc" crates/ai-env-cli/certs/claude-code-release.asc` and `gpg --homedir "$d" --dearmor < "$d/claude-code.asc" > crates/ai-env-cli/certs/claude-code-release.gpg`.
4. Change `RELEASE_KEY_FPR` (`src/wire/pin.rs`), `CLAUDE_GPG_FPR` (Makefile:83) and this file together: fingerprint, `fpr` line, sha256s, date.
5. `gpgv --status-fd 1 --keyring <the new .gpg, absolute> manifest.json.sig manifest.json` on a current release must give a GOODSIG and a VALIDSIG ending in the new fingerprint. Then `make test`, and `ai-env claude admit <v> --redo` for the versions that failed meanwhile.
