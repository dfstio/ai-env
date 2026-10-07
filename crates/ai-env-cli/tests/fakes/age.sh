#!/bin/sh
# Shared fake age toolchain for the S3 tests. One script, copied into a temp
# bin dir under each name the code looks up (AgeTool::probe needs `age` and
# `age-keygen`; `age-plugin-se` is there for doctor-style probes):
#   age            `--version` prints v1.3.2. `-e -R FILE` reads the plaintext
#                  on stdin and prints an age-shaped file: the real magic line
#                  (so container::read accepts it), one `-> fake-age <r>` line
#                  per recipient in FILE, a `--- fake-age` line, then the
#                  plaintext as lowercase hex, so the plaintext never appears
#                  verbatim in the output. `-d -i FILE` (exactly one -i, as
#                  ai-env always passes) reverses it. No temp files: stdin
#                  streams through od/awk, so "no plaintext on disk" holds.
#   age-keygen     `--version` only
#   age-plugin-se  `--version` only
# Environment:
#   FAKE_AGE_LOG   when set, each call's name and argv are appended here
#   FAKE_AGE_FAIL  encrypt|decrypt: that mode fails the way age does (exit 1);
#                  cancel: a decrypt fails as age-plugin-se does when the Touch
#                  ID dialog is dismissed (the text is provisional until a
#                  deliberate Cancel pins the real one in part B)
#   FAKE_AGE_DELAY_MS  a decrypt answers only after this long (a Touch ID that
#                  is granted slowly)
#   FAKE_AGE_HANG  a decrypt never answers: what an unanswered dialog looks
#                  like, for the deadline and the kill
#   FAKE_AGE_WAIT_FILE  a decrypt blocks until this file exists (at most 30 s):
#                  the proof that work overlaps the unseal
#   FAKE_AGE_PIDFILE    a hanging decrypt writes its pid here and logs
#                  `age TERM <pid>` to FAKE_AGE_LOG on SIGTERM, so a test can
#                  see the group signal arrive
set -u
me=$(basename "$0")
if [ -n "${FAKE_AGE_LOG:-}" ]; then
  printf '%s %s\n' "$me" "$*" >> "$FAKE_AGE_LOG"
fi
case "$me" in
  age-keygen|age-plugin-se)
    if [ "${1:-}" = --version ]; then
      if [ "$me" = age-plugin-se ]; then echo v0.2.1; else echo v1.3.2; fi
      exit 0
    fi
    echo "$me: error: the fake supports --version only" >&2
    exit 2 ;;
esac
if [ "${1:-}" = --version ]; then
  echo v1.3.2
  exit 0
fi

mode=
recipients=
identity=
ids=0
while [ $# -gt 0 ]; do
  case "$1" in
    -e|--encrypt) mode=e ;;
    -d|--decrypt) mode=d ;;
    -R|--recipients-file) shift; recipients=${1:-} ;;
    -i|--identity) shift; identity=${1:-}; ids=$((ids + 1)) ;;
    --) ;;
    *) cat > /dev/null; echo "age: error: fake age: unexpected argument $1" >&2; exit 1 ;;
  esac
  shift
done

if [ "$mode" = e ]; then
  if [ "${FAKE_AGE_FAIL:-}" = encrypt ]; then
    cat > /dev/null
    echo 'age: error: fake encryption failure' >&2
    exit 1
  fi
  if [ -z "$recipients" ] || [ ! -r "$recipients" ]; then
    cat > /dev/null
    echo "age: error: failed to open recipient file: $recipients" >&2
    exit 1
  fi
  printf 'age-encryption.org/v1\n'
  grep -v '^[[:space:]]*#' "$recipients" | grep -v '^[[:space:]]*$' | while IFS= read -r r; do
    printf -- '-> fake-age %s\n' "$r"
  done
  printf -- '--- fake-age\n'
  od -An -v -tx1 | tr -d ' \t\n'
  printf '\n'
  exit 0
fi

if [ "$mode" = d ]; then
  if [ "${FAKE_AGE_FAIL:-}" = decrypt ]; then
    cat > /dev/null
    echo 'age: error: fake decryption failure' >&2
    exit 1
  fi
  if [ "${FAKE_AGE_FAIL:-}" = cancel ]; then
    cat > /dev/null
    echo 'age: error: age-plugin-se: The operation couldn.t be completed. (kSecError error -128 - User canceled the operation.)' >&2
    exit 1
  fi
  if [ -n "${FAKE_AGE_PIDFILE:-}" ]; then
    printf '%s\n' "$$" > "$FAKE_AGE_PIDFILE"
    trap 'if [ -n "${FAKE_AGE_LOG:-}" ]; then printf "age TERM %s\n" "$$" >> "$FAKE_AGE_LOG"; fi; exit 143' TERM
  fi
  if [ -n "${FAKE_AGE_DELAY_MS:-}" ]; then
    # `sleep` takes a fraction on every shell the tests run on.
    sleep "$(awk -v ms="$FAKE_AGE_DELAY_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
  fi
  if [ -n "${FAKE_AGE_WAIT_FILE:-}" ]; then
    waited=0
    while [ ! -e "$FAKE_AGE_WAIT_FILE" ] && [ "$waited" -lt 3000 ]; do
      sleep 0.01
      waited=$((waited + 1))
    done
  fi
  if [ -n "${FAKE_AGE_HANG:-}" ]; then
    # Read stdin so the writer never blocks, then wait to be killed.
    cat > /dev/null
    while : ; do sleep 0.05; done
  fi
  if [ "$ids" -ne 1 ]; then
    cat > /dev/null
    echo "age: error: fake age wants exactly one -i (got $ids)" >&2
    exit 1
  fi
  if [ ! -r "$identity" ]; then
    cat > /dev/null
    echo "age: error: failed to open identity file: $identity" >&2
    exit 1
  fi
  # `exit` in a main rule still runs END, hence the `bad` flag.
  LC_ALL=C awk '
    function nib(c) { return index("0123456789abcdef", c) - 1 }
    NR == 1 { if ($0 != "age-encryption.org/v1") { bad = 1; exit 1 } next }
    body { hex = hex $0; next }
    /^--- / { body = 1; next }
    /^-> / { next }
    { bad = 1; exit 1 }
    END {
      if (bad || !body || length(hex) % 2) { print "age: error: not a fake-age file" > "/dev/stderr"; exit 1 }
      for (i = 1; i <= length(hex); i += 2) printf "%c", nib(substr(hex, i, 1)) * 16 + nib(substr(hex, i + 1, 1))
    }'
  exit $?
fi

cat > /dev/null
echo 'age: error: fake age needs -e or -d' >&2
exit 1
