#!/bin/sh
# Fake gpgv for S11's release trust (`ai-env claude admit` and `claude
# manifest`, bridge/claude/release.rs, through AI_ENV_BRIDGE_LAB_GPGV): no
# crypto. POSIX sh; runs under macOS /bin/sh.
#
# argv must be exactly `--status-fd 1 --homedir <dir> --keyring <abs path>
# <sig> <data>` (else exit 2, "fake gpgv: unexpected argv"), with <sig> and
# <data> present (else exit 2). gpgv runs with a cleared environment: the
# knobs come from `<this path>.knobs` only (every inherited FAKE_GPGV_* is
# unset first).
#
# Its keyring, as the real gpgv reads it: the --keyring file holds the
# vendored release key, 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
# (wire::pin::RELEASE_KEY_FPR), when its bytes are
# certs/claude-code-release.gpg's (by `cksum`: VENDORED_CKSUM below, renewed
# with that file), and no key otherwise. A signature by a key the keyring
# lacks is never good, bad, expired or revoked: it is `ERRSIG <keyid> 1 10 00
# <time> 9 -` and `NO_PUBKEY <keyid>`, and gpgv exits 2, whatever
# FAKE_GPGV_VERIFY says. The vendored keyring holds that one key (no subkey),
# so a signature by any other key reads `no_pubkey`, as with the real gpgv.
# FAKE_GPGV_VERIFY decides the rest (status lines on stdout, gpgv's text on
# stderr), FAKE_GPGV_PRIMARY being the signing key's primary fingerprint:
#   good               GOODSIG and a VALIDSIG naming FAKE_GPGV_PRIMARY first
#                      and last; exit 0
#   subkey             GOODSIG and a VALIDSIG naming a subkey first and
#                      FAKE_GPGV_PRIMARY last, as gpg does for a subkey's
#                      signature: good; exit 0
#   bad                a BADSIG line; exit 1 (the default)
#   mixed              two signatures: the release key's REVKEYSIG with its
#                      VALIDSIG naming FAKE_GPGV_PRIMARY, then one by
#                      FAKE_GPGV_OTHER (a key the keyring lacks: ERRSIG and
#                      NO_PUBKEY); exit 2
#   mixed-other-first  the same two signatures in the other order; exit 2
#   expired            EXPKEYSIG (the key expired) with a VALIDSIG naming
#                      FAKE_GPGV_PRIMARY; exit 0
#   revoked            REVKEYSIG alone (no other signature), its VALIDSIG
#                      naming FAKE_GPGV_PRIMARY; exit 0
#   no_pubkey          ERRSIG and NO_PUBKEY whatever the key (a keyring
#                      without it); exit 2
# (`subkey`, `expired` and `revoked` stand for what the release key may
# become: the vendored one has no subkey, no expiry and no revocation.)
# Knobs:
#   FAKE_GPGV_LOG      when set, each call's argv is appended here, one line
#   FAKE_GPGV_VERIFY   one of the above
#   FAKE_GPGV_PRIMARY  the signing key's primary fingerprint
#   FAKE_GPGV_OTHER    the other signature's key (mixed)
for v in $(env | sed -n 's/^\(FAKE_GPGV_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "$v"
done
case $0 in
  */*)
    if [ -f "$0.knobs" ]; then
      . "$0.knobs"
    fi
    ;;
esac
set -u
if [ -n "${FAKE_GPGV_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_GPGV_LOG"
fi
if [ "$#" -ne 8 ] || [ "$1" != "--status-fd" ] || [ "$2" != "1" ] || [ "$3" != "--homedir" ] || [ -z "$4" ] || [ "$5" != "--keyring" ]; then
  echo "fake gpgv: unexpected argv" >&2
  exit 2
fi
case "$6" in
  /*) ;;
  *) echo "fake gpgv: unexpected argv" >&2; exit 2 ;;
esac
if [ ! -f "$7" ] || [ ! -f "$8" ]; then
  echo "gpgv: can't open signed data or signature" >&2
  exit 2
fi
# The vendored keyring: its key's fingerprint, and `cksum < certs/claude-code-release.gpg`.
VENDORED_FPR=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
VENDORED_CKSUM='1426371610 1188'
held=
if [ "$(cksum < "$6" 2>/dev/null)" = "$VENDORED_CKSUM" ]; then
  held=$VENDORED_FPR
fi
primary=${FAKE_GPGV_PRIMARY:-}
other=${FAKE_GPGV_OTHER:-}
subkey=1111222233334444555566667777888899990000
code=0
# A v4 key's id: its fingerprint's last 16 hex digits.
keyid() {
  if [ "${#1}" -eq 40 ]; then
    printf '%s' "${1#????????????????????????}"
  else
    printf '0000111122223333'
  fi
}
validsig() {
  echo "[GNUPG:] VALIDSIG $1 2026-10-22 1792627200 0 4 0 1 10 00 $2"
}
# One signature by the key whose primary fingerprint is $1, of kind $2 (good,
# subkey, expired, revoked, else bad); one by a key the keyring lacks is
# ERRSIG and NO_PUBKEY whatever its kind.
signature() {
  echo "[GNUPG:] NEWSIG"
  id=$(keyid "$1")
  if [ -z "$held" ] || [ "$(printf '%s' "$1" | tr 'abcdef' 'ABCDEF')" != "$held" ]; then
    echo "[GNUPG:] ERRSIG $id 1 10 00 1792627200 9 -"
    echo "[GNUPG:] NO_PUBKEY $id"
    echo "gpgv: Can't check signature: No public key" >&2
    code=2
    return 0
  fi
  case "$2" in
    good)
      echo "[GNUPG:] GOODSIG $id Fake Release Signing"
      validsig "$1" "$1"
      echo "gpgv: Good signature from \"Fake Release Signing\"" >&2
      ;;
    subkey)
      echo "[GNUPG:] GOODSIG $(keyid "$subkey") Fake Release Signing"
      validsig "$subkey" "$1"
      echo "gpgv: Good signature from \"Fake Release Signing\"" >&2
      ;;
    expired)
      echo "[GNUPG:] KEYEXPIRED 1790000000"
      echo "[GNUPG:] EXPKEYSIG $id Fake Release Signing"
      validsig "$1" "$1"
      echo "gpgv: Good signature from \"Fake Release Signing\" (the key expired)" >&2
      ;;
    revoked)
      echo "[GNUPG:] REVKEYSIG $id Fake Release Signing"
      validsig "$1" "$1"
      echo "gpgv: WARNING: this key has been revoked by its owner" >&2
      ;;
    *)
      echo "[GNUPG:] BADSIG $id Fake Release Signing"
      echo "gpgv: BAD signature from \"Fake Release Signing\"" >&2
      if [ "$code" -eq 0 ]; then
        code=1
      fi
      ;;
  esac
}
verify=${FAKE_GPGV_VERIFY:-bad}
case "$verify" in
  good|subkey|expired|revoked)
    signature "$primary" "$verify" ;;
  mixed)
    signature "$primary" revoked
    signature "$other" good ;;
  mixed-other-first)
    signature "$other" good
    signature "$primary" revoked ;;
  no_pubkey)
    held=
    signature "$primary" good ;;
  *)
    signature "$primary" bad ;;
esac
exit "$code"
