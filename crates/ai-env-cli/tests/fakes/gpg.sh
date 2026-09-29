#!/bin/sh
# Fake gpg for `make claude-pin` (tests/infra/image.rs): no keyring, no
# crypto. Copied into a temp bin dir as `gpg`.
#   gpg --list-keys FPR                 exit 0 when FAKE_GPG_KEY=1 (the release
#                                       key is "imported"), else exit 2
#   gpg --status-fd 1 --verify SIG DAT  FAKE_GPG_VERIFY decides:
#     good  GOODSIG and VALIDSIG status lines on stdout; the VALIDSIG names
#           the signing subkey first and FAKE_GPG_PRIMARY (the primary-key
#           fingerprint) last, as gpg does; "Good signature" on stderr; exit 0
#     bad   a BADSIG status line, "BAD signature" on stderr, exit 1
#     mixed two signatures: the release key's is REVOKED (REVKEYSIG plus a
#           VALIDSIG naming FAKE_GPG_PRIMARY), then a GOOD one by another key
#           (FAKE_GPG_OTHER); exit 0, as gpg does when one signature is good
#     mixed-other-first  the same two signatures in the other order
# Environment:
#   FAKE_GPG_LOG      when set, each call's argv is appended here, one line
#   FAKE_GPG_KEY      1: the release key is in the keyring
#   FAKE_GPG_VERIFY   good | bad | mixed | mixed-other-first (default bad)
#   FAKE_GPG_PRIMARY  the primary-key fingerprint a good signature reports
#   FAKE_GPG_OTHER    the other key's fingerprint (mixed)
set -u
if [ -n "${FAKE_GPG_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_GPG_LOG"
fi
subkey=1111222233334444555566667777888899990000
keyid=7777888899990000
case "${1:-}" in
  --list-keys)
    if [ "${FAKE_GPG_KEY:-0}" = 1 ]; then
      echo "pub   ed25519 2025-01-01 [SC]"
      echo "      ${2:-}"
      exit 0
    fi
    echo "gpg: error reading key: No public key" >&2
    exit 2 ;;
  --status-fd)
    test "${2:-}" = 1 && test "${3:-}" = --verify || { echo "fake gpg: expected --status-fd 1 --verify SIG DATA" >&2; exit 2; }
    test -f "${4:-}" && test -f "${5:-}" || { echo "gpg: can't open signed data or signature" >&2; exit 2; }
    echo "[GNUPG:] NEWSIG"
    if [ "${FAKE_GPG_VERIFY:-bad}" = mixed-other-first ]; then
      echo "[GNUPG:] GOODSIG 0000111122223333 Someone Else"
      echo "[GNUPG:] VALIDSIG ${FAKE_GPG_OTHER:-} 2026-09-25 1790300000 0 4 0 22 10 00 ${FAKE_GPG_OTHER:-}"
      echo "[GNUPG:] NEWSIG"
      echo "[GNUPG:] REVKEYSIG $keyid Fake Release Signing"
      echo "[GNUPG:] VALIDSIG $subkey 2026-09-25 1790300000 0 4 0 22 10 00 ${FAKE_GPG_PRIMARY:-}"
      echo "gpg: Good signature from \"Someone Else\"" >&2
      exit 0
    fi
    if [ "${FAKE_GPG_VERIFY:-bad}" = mixed ]; then
      echo "[GNUPG:] REVKEYSIG $keyid Fake Release Signing"
      echo "[GNUPG:] VALIDSIG $subkey 2026-09-25 1790300000 0 4 0 22 10 00 ${FAKE_GPG_PRIMARY:-}"
      echo "[GNUPG:] NEWSIG"
      echo "[GNUPG:] GOODSIG 0000111122223333 Someone Else"
      echo "[GNUPG:] VALIDSIG ${FAKE_GPG_OTHER:-} 2026-09-25 1790300000 0 4 0 22 10 00 ${FAKE_GPG_OTHER:-}"
      echo "gpg: Good signature from \"Someone Else\"" >&2
      exit 0
    fi
    if [ "${FAKE_GPG_VERIFY:-bad}" = good ]; then
      echo "[GNUPG:] GOODSIG $keyid Fake Release Signing"
      echo "[GNUPG:] VALIDSIG $subkey 2026-09-25 1790300000 0 4 0 22 10 00 ${FAKE_GPG_PRIMARY:-}"
      echo "gpg: Good signature from \"Fake Release Signing\"" >&2
      exit 0
    fi
    echo "[GNUPG:] BADSIG $keyid Fake Release Signing"
    echo "gpg: BAD signature from \"Fake Release Signing\"" >&2
    exit 1 ;;
esac
echo "fake gpg: unsupported: $*" >&2
exit 2
