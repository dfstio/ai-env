#!/bin/sh
# Stand-in for the operator CLI in the recipe tests (tests/infra/image.rs:
# `make ... AI_ENV=<this>`): the recipes' wiring, not ai-env itself (the real
# binary has its own tests). No keystore and no age: the "sealed" container is
# a plain file naming the key id only; the secret is read and dropped.
#   creds aws-set --check           prints an [ok ] row, exit 0
#   creds aws-set --user U          reads the create-access-key JSON on stdin,
#                                   writes $AI_ENV_BRIDGE_DIR/credentials/aws.env
#                                   as `FAKE-SEALED <id>`, first copying an
#                                   existing one to aws.env.<unix seconds>.bak
#                                   (as aws-set does); no id on stdin: exit 1
#   run -f FILE [-k NAME] -- CMD    one decrypt (one Touch ID prompt): a -k
#                                   naming another key than FAKE_AIENV_KEY
#                                   fails like ai-env's strict choice (exit 4);
#                                   then CMD runs with the sealed id as
#                                   AWS_ACCESS_KEY_ID and a dummy secret
#   vm smoke ...                    prints FAKE_AIENV_SMOKE (one JSON record)
#                                   on stdout, exit FAKE_AIENV_SMOKE_RC (0)
#   egress reload ...               one line, exit FAKE_AIENV_RELOAD_RC (0)
#   egress status ...               one line, exit FAKE_AIENV_STATUS_RC (0); 1
#                                   also prints ai-env's "drift in
#                                   FAKE_AIENV_DRIFT" error, any other code
#                                   its "could not be verified" one
#   egress allow ...                one line, exit FAKE_AIENV_ALLOW_RC (0)
#   lab run ...                     one line, FAKE_AIENV_LAB_SLEEP seconds
#                                   (a probe that takes time), exit
#                                   FAKE_AIENV_LAB_RC (0); with
#                                   FAKE_AIENV_PEEK (the stateful aws fake's
#                                   state dir) the log line of `lab run
#                                   connector-pending ARN` also records that
#                                   connector's state at the time of the call,
#                                   and its end (after the sleep) writes the
#                                   connector's `peeked` marker, which releases
#                                   a connector the stateful aws fake holds
#                                   PENDING (create-hold)
#   proxy ...                       one line, exit FAKE_AIENV_PROXY_RC (0)
#   anything else                   (infra pin, infra base-image, ...) prints
#                                   one line, exit 0
# Environment:
#   FAKE_AIENV_LOG   each call's argv, and the AI_ENV variable it saw, one line
#                    (plus " [LAB=<names>]" when any AI_ENV_BRIDGE_LAB_* knob
#                    reached it)
#   FAKE_AIENV_KEY   the keystore key the container is sealed to
#                    (default ai-env-bridge)
#   FAKE_AIENV_SEAL  early: aws-set exits 1 before reading stdin; fail: after
#   FAKE_AIENV_RUN   cancel: `run` fails like a cancelled prompt (exit 3)
#   FAKE_AIENV_SEAL_DIR  aws-set seals under this bridge dir instead of
#                    AI_ENV_BRIDGE_DIR (a mis-resolved state root)
set -u
peek=
peeked=
if [ -n "${FAKE_AIENV_PEEK:-}" ] && [ "${1:-} ${2:-} ${3:-}" = "lab run connector-pending" ]; then
  c=${4:-}
  c=${c##*:network-connector:}
  c=${c%%:*}
  peek=" [state=$(awk '{ print $1; exit }' "$FAKE_AIENV_PEEK/connectors/$c/states" 2>/dev/null || true)]"
  peeked="$FAKE_AIENV_PEEK/connectors/$c/peeked"
fi
lab=$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | sort | tr '\n' ' ')
if [ -n "${FAKE_AIENV_LOG:-}" ]; then
  printf '%s [AI_ENV=%s]%s%s\n' "$*" "${AI_ENV-unset}" "$peek" "${lab:+ [LAB=${lab% }]}" >> "$FAKE_AIENV_LOG"
fi
case "${1:-} ${2:-}" in
  "vm smoke")
    printf '%s\n' "${FAKE_AIENV_SMOKE:-}"
    exit "${FAKE_AIENV_SMOKE_RC:-0}" ;;
  "egress reload")
    echo "fake ai-env: $*"
    exit "${FAKE_AIENV_RELOAD_RC:-0}" ;;
  "egress status")
    echo "fake ai-env: $*"
    case "${FAKE_AIENV_STATUS_RC:-0}" in
      0) ;;
      1) echo "ai-env: egress status: drift in ${FAKE_AIENV_DRIFT:-route-table}" >&2 ;;
      *) echo "ai-env: egress status: proxy could not be verified (see the rows)" >&2 ;;
    esac
    exit "${FAKE_AIENV_STATUS_RC:-0}" ;;
  "egress allow")
    echo "fake ai-env: $*"
    exit "${FAKE_AIENV_ALLOW_RC:-0}" ;;
  "lab run")
    echo "fake ai-env: $*"
    if [ -n "${FAKE_AIENV_LAB_SLEEP:-}" ]; then sleep "$FAKE_AIENV_LAB_SLEEP"; fi
    if [ -n "$peeked" ] && [ -d "${peeked%/peeked}" ]; then touch "$peeked"; fi
    exit "${FAKE_AIENV_LAB_RC:-0}" ;;
  "proxy "*)
    echo "fake ai-env: $*"
    exit "${FAKE_AIENV_PROXY_RC:-0}" ;;
  "creds aws-set")
    case " $* " in *" --check "*) echo "[ok ] fake aws-set --check"; exit 0 ;; esac
    if [ "${FAKE_AIENV_SEAL:-}" = early ]; then
      echo "ai-env: fake sealer failure before reading stdin" >&2
      exit 1
    fi
    input=$(cat)
    id=$(printf '%s\n' "$input" | sed -n 's/.*"AccessKeyId": *"\([A-Z0-9]*\)".*/\1/p' | head -1)
    if [ -z "$id" ] || [ "${FAKE_AIENV_SEAL:-}" = fail ]; then
      echo "ai-env: fake sealer: nothing sealed" >&2
      exit 1
    fi
    dir="${FAKE_AIENV_SEAL_DIR:-${AI_ENV_BRIDGE_DIR:?}}/credentials"
    mkdir -p "$dir"
    target="$dir/aws.env"
    bak=
    if [ -f "$target" ]; then
      bak="$target.$(date +%s).bak"
      test ! -e "$bak" || { echo "ai-env: cannot create backup $bak: exists" >&2; exit 1; }
      cp "$target" "$bak"
    fi
    printf 'FAKE-SEALED %s\n' "$id" > "$target"
    echo "sealed access key ...${id#????????????????} into $target (key ${FAKE_AIENV_KEY:-ai-env-bridge})"
    test -z "$bak" || echo "previous container kept as $bak"
    exit 0 ;;
esac
if [ "${1:-}" = run ]; then
  shift
  file=
  key=
  while [ $# -gt 0 ]; do
    case "$1" in
      -f) shift; file=${1:-} ;;
      -k) shift; key=${1:-} ;;
      --) shift; break ;;
      *) echo "fake ai-env run: unexpected argument $1" >&2; exit 2 ;;
    esac
    shift
  done
  if [ -n "$key" ] && [ "$key" != "${FAKE_AIENV_KEY:-ai-env-bridge}" ]; then
    echo "ai-env: key \"$key\" does not exist" >&2
    exit 4
  fi
  if [ "${FAKE_AIENV_RUN:-}" = cancel ]; then
    echo "ai-env: cancelled" >&2
    exit 3
  fi
  id=$(sed -n 's/^FAKE-SEALED //p' "$file" 2>/dev/null)
  test -n "$id" || { echo "ai-env: $file: not an ai-env container" >&2; exit 6; }
  AWS_ACCESS_KEY_ID=$id
  AWS_SECRET_ACCESS_KEY=$(printf 'Dm7/%.0s' 1 2 3 4 5 6 7 8 9 10)
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  exec "$@"
fi
echo "fake ai-env: $*"
exit 0
