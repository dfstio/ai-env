#!/bin/sh
# Stand-in for the operator CLI in the recipe tests (tests/infra/image.rs:
# `make ... AI_ENV=<this>`): the recipes' wiring, not ai-env itself (the real
# binary has its own tests). No keystore and no age: the "sealed" container is
# a plain file naming the key id only; the secret is read and dropped.
#   creds aws-set --check           prints an [ok ] row, exit 0 (with or
#                                   without --user; --user ai-env-deployer is
#                                   refused first, as below)
#   creds aws-set [--user U]        reads the create-access-key JSON on stdin,
#                                   writes $AI_ENV_BRIDGE_DIR/credentials/aws.env
#                                   (U ai-env-runtime, the default) or ops.env
#                                   (U ai-env-ops, S8) as `FAKE-SEALED <id>`,
#                                   first copying an existing one to <that
#                                   file>.<unix seconds>.bak (as aws-set does);
#                                   no id on stdin: exit 1. U ai-env-deployer:
#                                   refused, exit 9, stdin unread; any other U:
#                                   exit 2
#   creds aws-verify [--user U]     (S8) aws.env (U ai-env-runtime, the
#                                   default) or ops.env (U ai-env-ops) absent or
#                                   holding no FAKE-SEALED line: exit 5; one
#                                   decrypt; `id <id>`, then at most 6 tries of
#                                   `aws sts get-caller-identity --query Arn` as
#                                   that key alone (what apply_key leaves), 5 s
#                                   apart: `arn <arn>`, exit 0 for user/U, else
#                                   9; never answered: exit 5
#   creds deployer-key [--account A] [--clipboard-check]
#                                   (S8) --clipboard-check: one line, exit 0.
#                                   Else the create-access-key JSON on stdin (a
#                                   terminal: exit 2; another UserName: exit
#                                   9), `id <id>`, no --account: the
#                                   account-unknown refusal, exit 1 (the
#                                   stand-in reads no state/infra.toml or
#                                   bridge.toml, and key-issue always passes
#                                   --account), FAKE_AIENV_HANDOVER, then at
#                                   most 8 tries as the key alone: `arn <arn>`,
#                                   exit 0 for user/ai-env-deployer of account
#                                   A, else 9; never answered: 42. Every
#                                   failure past the parse prints the cleanup
#                                   note (the delete command)
#   as IDENTITY [--account A] [--check] [--] [CMD...]
#                                   (S8) the runner. An unparseable marker, or a
#                                   key marker whose key is not in the
#                                   environment (AWS_ACCESS_KEY_ID ending in its
#                                   tail, a 40-character secret): its refusal,
#                                   exit 9, --check included. --check: exit 0
#                                   when AI_ENV_BRIDGE_AS covers IDENTITY, else
#                                   9. A covering marker (but for root) execs
#                                   CMD as is. root, ambient: refused under
#                                   another marker (9), then `aws sts
#                                   get-caller-identity --query Arn` (PATH's
#                                   aws) must (root) or must not (ambient) be
#                                   the account root (9; no answer: 5); exec with
#                                   the marker root or ambient. deployer, ops:
#                                   FAKE_AIENV_AS, then exec as the key of tail
#                                   9001 or 9002 (the 14 credential selectors
#                                   and the AWS_CONTAINER_*, AWS_ENDPOINT_URL*
#                                   names unset, the 7 pins set, a 40-character
#                                   secret) with the marker deployer:9001 or
#                                   ops:9002
#   run -f FILE [-k NAME] -- CMD    one decrypt (one Touch ID prompt): a -k
#                                   naming another key than FAKE_AIENV_KEY
#                                   fails like ai-env's strict choice (exit 4);
#                                   then CMD runs with the sealed id as
#                                   AWS_ACCESS_KEY_ID and a dummy secret, and
#                                   without AI_ENV_BRIDGE_AS (S8: ai-env run
#                                   drops it)
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
#   infra pin --bundle-version      prints FAKE_AIENV_BUNDLE, exit 0; unset or
#                                   empty: ai-env's no-bundle error, exit 1
#   egress check ...                one line, exit FAKE_AIENV_CHECK_RC (0)
#   anything else                   (infra pin, infra base-image, ...) prints
#                                   one line, exit 0
# Environment:
#   FAKE_AIENV_LOG   each call's argv, and the AI_ENV variable it saw, one line
#                    (plus " [LAB=<names>]" when any AI_ENV_BRIDGE_LAB_* knob
#                    reached it, then " [AS=<marker>]" when AI_ENV_BRIDGE_AS
#                    is set, then " [PASTE=<value>]" when the debug builds'
#                    paste knob AI_ENV_PASTE_STDIN reached it)
#   FAKE_AIENV_KEY   the keystore key the container is sealed to
#                    (default ai-env-bridge)
#   FAKE_AIENV_SEAL  early: aws-set exits 1 before reading stdin; fail: after
#   FAKE_AIENV_RUN   cancel: `run` and `creds aws-verify` fail like a cancelled
#                    prompt (exit 3)
#   FAKE_AIENV_SEAL_DIR  aws-set seals under this bridge dir instead of
#                    AI_ENV_BRIDGE_DIR (a mis-resolved state root)
#   FAKE_AIENV_AS    (S8) cancel: `as deployer` fails like an empty paste (its
#                    one line, exit 3), `as ops` like a dismissed Touch ID
#                    (`ai-env: cancelled`, exit 3); refused: `as deployer` like
#                    a key AWS refuses (exit 5); foreign: like another user's
#                    key (exit 9)
#   FAKE_AIENV_HANDOVER  (S8) cancel (exit 3), mismatch (exit 1) or clipboard
#                    (exit 1): `creds deployer-key` fails that way after `id`
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
  printf '%s [AI_ENV=%s]%s%s%s%s\n' "$*" "${AI_ENV-unset}" "$peek" "${lab:+ [LAB=${lab% }]}" "${AI_ENV_BRIDGE_AS:+ [AS=$AI_ENV_BRIDGE_AS]}" "${AI_ENV_PASTE_STDIN:+ [PASTE=$AI_ENV_PASTE_STDIN]}" >> "$FAKE_AIENV_LOG"
fi

# ---- S8: the runner's marker and the key checks (plans/s8-operators-contracts.md §2, §3, §5.2, §6) ----
selectors="AWS_PROFILE AWS_DEFAULT_PROFILE AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_CREDENTIAL_EXPIRATION AWS_ACCESS_KEY
  AWS_SECRET_KEY AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_ACCOUNT_ID AWS_SDK_LOAD_CONFIG
  AWS_EC2_METADATA_SERVICE_ENDPOINT AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE"
tc='[0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ]'
tail4() { printf '%s' "${1#"${1%????}"}"; }
# key_env <id>: what apply_key leaves for an aws child: the 14 credential selectors and every AWS_CONTAINER_* and
# AWS_ENDPOINT_URL* name unset, the 7 pins set, the key <id> with a 40-character secret built here.
key_env() {
  for n in $selectors $(env | sed -n 's/^\(AWS_CONTAINER_[A-Za-z0-9_]*\)=.*/\1/p; s/^\(AWS_ENDPOINT_URL[A-Za-z0-9_]*\)=.*/\1/p'); do
    unset "$n"
  done
  AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true
  AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true AWS_REGION=eu-central-1 AWS_DEFAULT_REGION=eu-central-1 AWS_PAGER=
  AWS_ACCESS_KEY_ID=$1
  AWS_SECRET_ACCESS_KEY=$(printf 'Dm7/%.0s' 1 2 3 4 5 6 7 8 9 10)
  export AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_EC2_METADATA_DISABLED AWS_IGNORE_CONFIGURED_ENDPOINT_URLS \
    AWS_REGION AWS_DEFAULT_REGION AWS_PAGER AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
}
# first_line <text>: its first line that is not blank.
first_line() { printf '%s\n' "$1" | sed '/^[[:space:]]*$/d' | head -1; }
# arn_of <answer>: the Arn of a get-caller-identity answer, text (--query Arn) or JSON.
arn_of() {
  a=$(printf '%s\n' "$1" | sed -n 's/.*"Arn": *"\([^"]*\)".*/\1/p' | head -1)
  if [ -n "$a" ]; then printf '%s' "$a"; else first_line "$1"; fi
}
# refusal_of <stderr>: the error code when it is one a refused key gets, else nothing.
refusal_of() {
  printf '%s\n' "$1" | sed -n -E 's/.*\((InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException|AuthFailure|InvalidAccessKeyId|ExpiredToken)\).*/\1/p' | head -1
}
# sts_loop <tries> <label> <id>: at most <tries> calls of `aws sts get-caller-identity --query Arn` as the key <id>
# alone (key_env, the marker unset), 5 s apart with the retry note; status 0 with `arn` set, or 1 with `last` (the
# refusal's code, else the first line of the last failure).
sts_loop() {
  key_env "$3"
  unset AI_ENV_BRIDGE_AS
  i=1
  while :; do
    if out=$(aws sts get-caller-identity --region eu-central-1 --query Arn --output text 2>&1); then
      arn=$(arn_of "$out")
      return 0
    fi
    last=$(refusal_of "$out")
    why="IAM propagation"
    if [ -z "$last" ]; then
      last=$(first_line "$out")
      why=$last
    fi
    test "$i" -lt "$1" || return 1
    echo "ai-env: $2 ...$(tail4 "$3") does not answer yet ($i/$1: $why)" >&2
    sleep 5
    i=$((i + 1))
  done
}
# marker: AI_ENV_BRIDGE_AS as m_word (deployer, ops, root or ambient; empty when unset or empty; bad when
# unparseable) and m_tail, with m_fault (id or secret) for a key marker whose key is not in the environment.
marker() {
  m_word=
  m_tail=
  m_fault=
  case "${AI_ENV_BRIDGE_AS:-}" in
    '') ;;
    root|ambient) m_word=$AI_ENV_BRIDGE_AS ;;
    deployer:$tc$tc$tc$tc|ops:$tc$tc$tc$tc)
      m_word=${AI_ENV_BRIDGE_AS%%:*}
      m_tail=${AI_ENV_BRIDGE_AS#*:}
      case "${AWS_ACCESS_KEY_ID:-}" in
        *"$m_tail") ;;
        *) m_fault=id ;;
      esac
      ms=${AWS_SECRET_ACCESS_KEY:-}
      if [ -z "$m_fault" ] && [ "${#ms}" -ne 40 ]; then m_fault=secret; fi
      ms= ;;
    *) m_word=bad ;;
  esac
}
# covers <identity>: the marker covers it (contracts §2.3).
covers() {
  test -n "$m_word" && test "$m_word" != bad && test -z "$m_fault" || return 1
  case "$m_word:$1" in
    deployer:deployer|deployer:ops|ops:ops|root:deployer|root:ops|root:root|ambient:ops|ambient:ambient) return 0 ;;
  esac
  return 1
}
# marker_refusal: the §2.5 text of an unparseable marker, or of a key marker without its key.
marker_refusal() {
  if [ "$m_word" = bad ]; then
    printf 'AI_ENV_BRIDGE_AS=%.40s is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it' "$AI_ENV_BRIDGE_AS"
  elif [ "$m_fault" = id ]; then
    printf 'AI_ENV_BRIDGE_AS names the %s key ...%s, but AWS_ACCESS_KEY_ID holds another key (or none): something between ai-env as and this command changed it; run the command directly under ai-env as %s --' "$m_word" "$m_tail" "$m_word"
  else
    printf 'AI_ENV_BRIDGE_AS names the %s key ...%s, but AWS_SECRET_ACCESS_KEY is missing or not a secret access key: run the command directly under ai-env as %s --' "$m_word" "$m_tail" "$m_word"
  fi
}
# who_of <identity>: how the --check refusal names it.
who_of() {
  case "$1" in
    deployer) printf 'ai-env-deployer' ;;
    ops) printf 'ai-env-ops' ;;
    root) printf 'the account root' ;;
    *) printf 'the ambient aws CLI identity' ;;
  esac
}
# run_cmd CMD...: exec it, or ai-env's refusal when it cannot be run.
run_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ai-env: cannot exec \"$1\": No such file or directory (os error 2)" >&2; exit 1; }
  exec "$@"
}
# user_of ARGS...: the value of --user (default ai-env-runtime).
user_of() {
  u=ai-env-runtime
  while [ $# -gt 0 ]; do
    case "$1" in
      --user) shift; u=${1:-} ;;
      --user=*) u=${1#--user=} ;;
    esac
    test $# -eq 0 || shift
  done
  printf '%s' "$u"
}
# as_writer: the runner every `aws iam` command ai-env prints starts with (its identity::writer_runner, D13; a bare aws
# has no credentials on the Mac): the root's under the marker root, the ambient one under ambient, else the deployer's.
as_writer() {
  case "${AI_ENV_BRIDGE_AS:-}" in
    root) printf 'ai-env as root -- ' ;;
    ambient) printf 'ai-env as ambient -- ' ;;
    *) printf 'ai-env as deployer -- ' ;;
  esac
}
# cleanup_note <user> <id> [matched]: the delete command of a key that was NOT handed over (contracts §6.3).
cleanup_note() {
  printf 'the access key ...%s of IAM user %s was NOT handed over; if you just created it, delete it:\n  %saws iam delete-access-key --user-name %s --access-key-id %s --region eu-central-1\n' \
    "$(tail4 "$2")" "$1" "$(as_writer)" "$1" "$2" >&2
  if [ -n "${3:-}" ]; then
    echo '  and clear the Strongbox entry (its history keeps the previous values)' >&2
  fi
}

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
  "infra pin")
    case " $* " in
      *" --bundle-version "*)
        if [ -n "${FAKE_AIENV_BUNDLE:-}" ]; then echo "$FAKE_AIENV_BUNDLE"; exit 0; fi
        echo "ai-env: pin: no anthropic.claude-code-<version>-darwin-arm64 bundle under the extensions directory" >&2
        exit 1 ;;
    esac
    echo "fake ai-env: $*"
    exit 0 ;;
  "egress check")
    echo "fake ai-env: $*"
    exit "${FAKE_AIENV_CHECK_RC:-0}" ;;
  "creds aws-set")
    u=$(user_of "$@")
    # The deployer's key is refused before anything is read, --check included (contracts §5.1).
    if [ "$u" = ai-env-deployer ]; then
      echo "ai-env: --user ai-env-deployer: the deployer's key is never stored on this Mac: it lives in Strongbox and is pasted per command (ai-env as deployer -- …); hand a new one over with: $(as_writer)aws iam create-access-key --user-name ai-env-deployer --output json | ai-env creds deployer-key" >&2
      exit 9
    fi
    case " $* " in *" --check "*) echo "[ok ] fake aws-set --check"; exit 0 ;; esac
    case "$u" in
      ai-env-runtime) file=aws.env ;;
      ai-env-ops) file=ops.env ;;
      *)
        echo "ai-env: --user \"$u\": aws-set seals ai-env-runtime (credentials/aws.env) or ai-env-ops (credentials/ops.env)" >&2
        exit 2 ;;
    esac
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
    target="$dir/$file"
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
  "creds aws-verify")
    u=$(user_of "$@")
    case "$u" in
      ai-env-runtime) file=aws.env; what=runtime; hint="make runtime-key" ;;
      ai-env-ops) file=ops.env; what=ops; hint="ai-env as deployer -- make ops-key" ;;
      ai-env-deployer)
        echo "ai-env: --user ai-env-deployer: its key is never sealed here: check it with ai-env as deployer -- true" >&2
        exit 9 ;;
      *)
        echo "ai-env: --user \"$u\": aws-verify checks ai-env-runtime (credentials/aws.env) or ai-env-ops (credentials/ops.env)" >&2
        exit 2 ;;
    esac
    sealed="${AI_ENV_BRIDGE_DIR:?}/credentials/$file"
    if [ ! -e "$sealed" ]; then
      echo "ai-env: $sealed does not exist: seal the $what key with $hint" >&2
      exit 5
    fi
    id=$(sed -n 's/^FAKE-SEALED //p' "$sealed" 2>/dev/null | head -1)
    if [ -z "$id" ]; then
      echo "ai-env: $sealed is not an ai-env container: move it away (and rotate the key it may hold: $hint ROTATE=1)" >&2
      exit 5
    fi
    # The decrypt (one Touch ID prompt).
    if [ "${FAKE_AIENV_RUN:-}" = cancel ]; then
      echo "ai-env: cancelled" >&2
      exit 3
    fi
    test -t 1 || echo "id $id"
    t=$(tail4 "$id")
    if ! sts_loop 6 "the sealed key" "$id"; then
      echo "ai-env: aws-verify: the sealed key ...$t never answered (6 tries, 5 s apart; last: $last)" >&2
      exit 5
    fi
    test -t 1 || echo "arn $arn"
    case "$arn" in
      *:user/"$u")
        echo "ai-env: aws-verify: the sealed key ...$t answers as user/$u" >&2
        exit 0 ;;
      *:root)
        echo "ai-env: aws-verify: the sealed key ...$t is the account ROOT's: never seal it (delete it in the IAM console)" >&2
        exit 9 ;;
      *)
        echo "ai-env: aws-verify: the sealed key ...$t answers as $arn, not user/$u" >&2
        exit 9 ;;
    esac ;;
  "creds deployer-key")
    shift 2
    account=
    clip=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --account) shift; account=${1:-} ;;
        --account=*) account=${1#--account=} ;;
        --clipboard-check) clip=1 ;;
      esac
      test $# -eq 0 || shift
    done
    if [ "$clip" = 1 ]; then
      if [ -n "$account" ]; then
        echo "error: the argument '--clipboard-check' cannot be used with '--account <ACCOUNT>'" >&2
        exit 2
      fi
      echo "ai-env: clipboard check: the marker FakeMarker12 is on the clipboard, this Mac only and concealed: try to paste it on another Apple device now; it must NOT paste there" >&2
      exit 0
    fi
    if [ -t 0 ]; then
      echo "ai-env: stdin is a terminal: pipe the JSON of aws iam create-access-key --user-name ai-env-deployer --output json into this command; never paste it" >&2
      exit 2
    fi
    # The secret is read and dropped, as in aws-set.
    input=$(cat)
    id=$(printf '%s\n' "$input" | sed -n 's/.*"AccessKeyId": *"\([A-Z0-9]*\)".*/\1/p' | head -1)
    owner=$(printf '%s\n' "$input" | sed -n 's/.*"UserName": *"\([^"]*\)".*/\1/p' | head -1)
    input=
    if [ -z "$id" ] || [ -z "$owner" ]; then
      w=$(as_writer)
      printf 'ai-env: stdin is not the JSON of aws iam create-access-key\nno access key was stored; if aws iam create-access-key succeeded, find the new key and delete it:\n  %saws iam list-access-keys --user-name ai-env-deployer --region eu-central-1\n  %saws iam delete-access-key --user-name ai-env-deployer --access-key-id <id> --region eu-central-1\n' "$w" "$w" >&2
      exit 1
    fi
    if [ "$owner" != ai-env-deployer ]; then
      echo "ai-env: the access key belongs to IAM user \"$owner\", not \"ai-env-deployer\": refusing to hand over another principal's key" >&2
      cleanup_note "$owner" "$id"
      exit 9
    fi
    test -t 1 || echo "id $id"
    t=$(tail4 "$id")
    # The stand-in has no state/infra.toml or bridge.toml to read: the account is --account's or unknown (D10).
    if [ -z "$account" ]; then
      echo "ai-env: creds deployer-key: the stack's account is unknown here (no state/infra.toml, no [aws] ARN in bridge.toml): pass --account with its 12 digits" >&2
      cleanup_note ai-env-deployer "$id"
      exit 1
    fi
    case "${FAKE_AIENV_HANDOVER:-}" in
      cancel)
        echo "ai-env: creds deployer-key: nothing was pasted back: cancelled, it was NOT handed over" >&2
        cleanup_note ai-env-deployer "$id"
        exit 3 ;;
      mismatch)
        echo "ai-env: creds deployer-key: the access key id pasted back never matched the one created (3 rounds): it was NOT handed over" >&2
        cleanup_note ai-env-deployer "$id"
        exit 1 ;;
      clipboard)
        echo "ai-env: the clipboard could not be set this-Mac-only and concealed (execution error: Error: Error: setString:forType: refused (-2700)): cleared, so nothing of the key is on it. Delete the key, then create the deployer's key in the IAM console (Users → ai-env-deployer → Security credentials → Create access key), copy both into Strongbox there (never download the .csv), and check it with: ai-env as deployer -- true" >&2
        cleanup_note ai-env-deployer "$id"
        exit 1 ;;
    esac
    # The paste-back matched: from here the note also asks to clear the Strongbox entry.
    if ! sts_loop 8 "the key" "$id"; then
      echo "ai-env: creds deployer-key: the key ...$t never answered (8 tries, 5 s apart; last: $last): it was NOT handed over" >&2
      cleanup_note ai-env-deployer "$id" matched
      exit 42
    fi
    test -t 1 || echo "arn $arn"
    of=$(printf '%s' "$arn" | cut -d: -f5)
    case "$arn" in
      *:root) why="the key ...$t is the account ROOT's: never paste it here (the deployer's key is its own Strongbox entry); delete root's access key" ;;
      *:user/ai-env-deployer)
        if [ "$of" = "$account" ]; then
          echo "ai-env: the access key ...$t answers as user/ai-env-deployer: it is in Strongbox only; ai-env as deployer -- … asks for it" >&2
          exit 0
        fi
        why="the key ...$t is ai-env-deployer of account $of, but the stack (--account) is in account $account" ;;
      *) why="the key ...$t answers as $arn, not ai-env-deployer" ;;
    esac
    echo "ai-env: creds deployer-key: $why: it was NOT handed over" >&2
    cleanup_note ai-env-deployer "$id" matched
    exit 9 ;;
esac
if [ "${1:-}" = as ]; then
  shift
  who=
  check=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --check) check=1 ;;
      --account)
        shift
        test $# -gt 0 || { echo "error: a value is required for '--account <ACCOUNT>' but none was supplied" >&2; exit 2; } ;;
      --account=*) ;;
      --) shift; break ;;
      -*)
        test -z "$who" || break
        echo "error: unexpected argument '$1' found" >&2
        exit 2 ;;
      *)
        test -z "$who" || break
        who=$1 ;;
    esac
    shift
  done
  if [ -z "$who" ] && [ $# -gt 0 ]; then
    who=$1
    shift
  fi
  case "$who" in
    deployer|ops|root|ambient) ;;
    *) echo "error: invalid value '$who' for '<IDENTITY>' [possible values: deployer, ops, root, ambient]" >&2; exit 2 ;;
  esac
  if [ "$check" = 1 ] && [ $# -gt 0 ]; then
    echo "error: the argument '--check' cannot be used with '[COMMAND]...'" >&2
    exit 2
  fi
  if [ "$check" = 0 ] && [ $# -eq 0 ]; then
    echo "error: the following required arguments were not provided: [COMMAND]..." >&2
    exit 2
  fi
  marker
  if [ "$check" = 1 ]; then
    # A marker ai-env never sets, or a key marker without its key: its own refusal (contracts §2.5, §3.3).
    if [ "$m_word" = bad ] || [ -n "$m_fault" ]; then
      echo "ai-env: $(marker_refusal)" >&2
      exit 9
    fi
    covers "$who" && exit 0
    echo "ai-env: as --check $who: this process does not run as $(who_of "$who"): run it as ai-env as $who -- <command>" >&2
    exit 9
  fi
  # A covering marker runs CMD at once, as it is (as root is refused under every marker, its own included).
  if [ "$who" != root ] && covers "$who"; then
    run_cmd "$@"
  fi
  case "$who" in
    root|ambient)
      if [ "$m_word" = bad ]; then
        echo "ai-env: $(marker_refusal)" >&2
        exit 9
      fi
      if [ -n "$m_word" ]; then
        echo "ai-env: as $who: already inside ai-env as $m_word (AI_ENV_BRIDGE_AS): start it from a terminal of its own" >&2
        exit 9
      fi
      # The aws CLI's own chain, the environment untouched.
      if ! out=$(aws sts get-caller-identity --region eu-central-1 --query Arn --output text 2>&1); then
        if [ "$who" = root ]; then
          echo "ai-env: as root: no AWS credentials answer ($(first_line "$out")): ai-env as root needs the account root's access key in this shell (README \"Break-glass\")" >&2
        else
          echo "ai-env: as ambient: no AWS credentials answer ($(first_line "$out"))" >&2
        fi
        exit 5
      fi
      arn=$(arn_of "$out")
      if [ "$who" = root ]; then
        case "$arn" in
          *:root) ;;
          *)
            echo "ai-env: as root: the aws CLI's credentials are $arn, not the account root: ai-env as root is only for the bootstrap deploy and break-glass" >&2
            exit 9 ;;
        esac
      else
        case "$arn" in
          *:root)
            echo "ai-env: as ambient: the aws CLI's credentials are the account ROOT: operator commands run as ai-env as ops --, deploys as ai-env as deployer --, the bootstrap alone as ai-env as root --" >&2
            exit 9 ;;
        esac
      fi
      AI_ENV_BRIDGE_AS=$who
      export AI_ENV_BRIDGE_AS
      run_cmd "$@" ;;
    *)
      if [ "$m_word" = bad ] || [ -n "$m_fault" ]; then
        echo "ai-env: $(marker_refusal)" >&2
        exit 9
      fi
      # The paste (deployer: an empty one is its own line, contracts D19) or the Touch ID of ops.env (ops: a
      # dismissed dialog is ai-env's plain cancel).
      if [ "${FAKE_AIENV_AS:-}" = cancel ]; then
        if [ "$who" = deployer ]; then
          echo "ai-env: as deployer: nothing was pasted: cancelled, nothing was run" >&2
        else
          echo "ai-env: cancelled" >&2
        fi
        exit 3
      fi
      t=9002
      if [ "$who" = deployer ]; then
        t=9001
        case "${FAKE_AIENV_AS:-}" in
          refused)
            echo "ai-env: as deployer: AWS refused the key ...$t (InvalidClientTokenId): a deleted or deactivated key, or the secret of another key: nothing was run" >&2
            exit 5 ;;
          foreign)
            echo "ai-env: as deployer: the key ...$t answers as arn:aws:iam::123456789012:user/rust, not ai-env-deployer: nothing was run" >&2
            exit 9 ;;
        esac
      fi
      key_env "$(printf 'AKIAFAKE%012d' "$t")"
      AI_ENV_BRIDGE_AS=$who:$t
      export AI_ENV_BRIDGE_AS
      run_cmd "$@" ;;
  esac
fi
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
  unset AI_ENV_BRIDGE_AS
  exec "$@"
fi
echo "fake ai-env: $*"
exit 0
