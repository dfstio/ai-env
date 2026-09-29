#!/bin/sh
# Stateful fake `aws` for the recipe tests (tests/infra/image.rs: runtime-key,
# ops.sh wait): never talks to AWS. Copied into a temp bin dir as `aws`. The
# state lives in plain files under FAKE_AWS_STATE, which the test seeds and
# reads. Every call must carry `--region eu-central-1` (else exit 252). Key
# ids are AKIAFAKE + a 12-digit counter; the secret is built at run time.
#   iam list-access-keys --query 'AccessKeyMetadata[].AccessKeyId'  the ids in
#       $S/keys, tab-separated (the text output); a `sort_by(...)[-1]...`
#       query prints the newest id
#   iam create-access-key      appends the next id ($S/next, default 1) to
#       $S/keys and prints the CLI's JSON; at 2 keys LimitExceeded (exit 254).
#       FAKE_AWS_CREATE=fail: no key, exit 254; =lost: the key is created but
#       the response is lost (nothing printed, exit 255); =twice: a retried
#       call left an extra key first (two new ids, the second one printed)
#   FAKE_AWS_LIST_FAIL_FROM=N  the N-th list-access-keys call and every later
#       one fail (Throttling, 254)
#   iam delete-access-key --access-key-id K   removes K (NoSuchEntity: 254)
#   sts get-caller-identity    with AWS_ACCESS_KEY_ID set: a key in $S/keys
#       answers as user/FAKE_AWS_KEY_USER (default ai-env-runtime) once the
#       first $S/sts-fails calls have failed (InvalidClientTokenId, 254, like
#       a key IAM has not propagated); any other key fails the same way.
#       Unset: the deploy identity user/rust. Account 123456789012. A session
#       token next to the key (AWS_SESSION_TOKEN or AWS_SECURITY_TOKEN, e.g.
#       leaked from the operator's shell) makes it fail like AWS does.
#   lambda-microvms list-microvm-images      prints the name when $S/image/state
#       exists
#   lambda-microvms get-microvm-image        JSON of $S/image/{state,active,
#       failed,updated}; with --query '[f1,f2,...]' --output text those fields
#       tab-separated, None for a missing one
#   lambda-microvms list-microvm-image-versions   {"items": []}
# Environment:
#   FAKE_AWS_LOG     when set, each call's argv is appended here, one line
#   FAKE_AWS_STATE   the state directory (required)
set -u
if [ -n "${FAKE_AWS_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_AWS_LOG"
fi
S=${FAKE_AWS_STATE:?}
mkdir -p "$S"
region=
user=
key=
query=
name=
prev=
for a in "$@"; do
  case "$prev" in
    --region) region=$a ;;
    --user-name) user=$a ;;
    --access-key-id) key=$a ;;
    --query) query=$a ;;
    --name-filter) name=$a ;;
  esac
  prev=$a
done
if [ "$region" != eu-central-1 ]; then
  echo 'fake aws: every call must carry --region eu-central-1' >&2
  exit 252
fi
touch "$S/keys"
acct=123456789012
key_id() { printf 'AKIAFAKE%012d' "$1"; }
err() { printf '\nAn error occurred (%s) when calling the %s operation: %s\n' "$1" "$2" "$3" >&2; exit "${4:-254}"; }
field() {
  case "$1" in
    state) f=state ;;
    latestActiveImageVersion) f=active ;;
    latestFailedImageVersion) f=failed ;;
    updatedAt) f=updated ;;
    *) f=none ;;
  esac
  if [ -s "$S/image/$f" ]; then cat "$S/image/$f"; else printf 'None'; fi
}

case "${1:-} ${2:-}" in
  "iam list-access-keys")
    calls=$(( $(cat "$S/list-calls" 2>/dev/null || echo 0) + 1 ))
    echo "$calls" >"$S/list-calls"
    if [ -n "${FAKE_AWS_LIST_FAIL_FROM:-}" ] && [ "$calls" -ge "$FAKE_AWS_LIST_FAIL_FROM" ]; then
      err Throttling ListAccessKeys "Rate exceeded"
    fi
    case "$query" in
      'AccessKeyMetadata[].AccessKeyId') paste -s -d '\t' "$S/keys" ;;
      sort_by*) tail -1 "$S/keys" ;;
      *) echo "fake aws: unsupported list-access-keys query: $query" >&2; exit 2 ;;
    esac ;;
  "iam create-access-key")
    case "${FAKE_AWS_CREATE:-}" in
      fail) err ServiceFailure CreateAccessKey "the fake refuses to create a key" ;;
    esac
    test "$(wc -l <"$S/keys" | tr -d ' ')" -lt 2 || err LimitExceeded CreateAccessKey "Cannot exceed quota for AccessKeysPerUser: 2" 254
    n=$(cat "$S/next" 2>/dev/null || echo 1)
    if [ "${FAKE_AWS_CREATE:-}" = twice ]; then
      key_id "$n" >>"$S/keys"
      echo >>"$S/keys"
      n=$((n + 1))
    fi
    echo $((n + 1)) >"$S/next"
    id=$(key_id "$n")
    echo "$id" >>"$S/keys"
    test "${FAKE_AWS_CREATE:-}" != lost || exit 255
    secret=$(printf 'Fk9/%.0s' 1 2 3 4 5 6 7 8 9 10)
    printf '{\n    "AccessKey": {\n        "UserName": "%s",\n        "AccessKeyId": "%s",\n        "Status": "Active",\n        "SecretAccessKey": "%s",\n        "CreateDate": "2026-09-29T10:00:00+00:00"\n    }\n}\n' \
      "$user" "$id" "$secret" ;;
  "iam delete-access-key")
    grep -qxF -- "$key" "$S/keys" || err NoSuchEntity DeleteAccessKey "The Access Key with id $key cannot be found."
    grep -vxF -- "$key" "$S/keys" >"$S/keys.tmp" || true
    mv "$S/keys.tmp" "$S/keys" ;;
  "sts get-caller-identity")
    who=rust
    if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
      if [ -n "${AWS_SESSION_TOKEN:-}${AWS_SECURITY_TOKEN:-}" ]; then
        err InvalidClientTokenId GetCallerIdentity "The security token included in the request is invalid."
      fi
      grep -qxF -- "$AWS_ACCESS_KEY_ID" "$S/keys" || err InvalidClientTokenId GetCallerIdentity "The security token included in the request is invalid."
      fails=$(cat "$S/sts-fails" 2>/dev/null || echo 0)
      if [ "$fails" -gt 0 ]; then
        echo $((fails - 1)) >"$S/sts-fails"
        err InvalidClientTokenId GetCallerIdentity "The security token included in the request is invalid."
      fi
      who=${FAKE_AWS_KEY_USER:-ai-env-runtime}
    fi
    arn="arn:aws:iam::$acct:user/$who"
    case "$query" in
      Arn) echo "$arn" ;;
      Account) echo "$acct" ;;
      *) printf '{\n    "UserId": "AIDAFAKEFAKEFAKEFAKE",\n    "Account": "%s",\n    "Arn": "%s"\n}\n' "$acct" "$arn" ;;
    esac ;;
  "lambda-microvms list-microvm-images")
    if [ -f "$S/image/state" ]; then echo "$name"; fi ;;
  "lambda-microvms get-microvm-image")
    test -f "$S/image/state" || err ResourceNotFoundException GetMicrovmImage "Image not found"
    case "$query" in
      '')
        printf '{\n    "name": "ai-env-agent"'
        for f in state latestActiveImageVersion latestFailedImageVersion updatedAt; do
          v=$(field "$f")
          test "$v" = None || printf ',\n    "%s": "%s"' "$f" "$v"
        done
        printf '\n}\n' ;;
      \[*\])
        list=${query#\[}
        list=${list%\]}
        out=
        sep=
        for f in $(echo "$list" | tr ',' ' '); do
          out="$out$sep$(field "$f")"
          sep=$(printf '\t')
        done
        printf '%s\n' "$out" ;;
      *) printf '%s\n' "$(field "$query")" ;;
    esac ;;
  "lambda-microvms list-microvm-image-versions")
    test -f "$S/image/state" || err ResourceNotFoundException ListMicrovmImageVersions "Image not found"
    echo '{"items": []}' ;;
  *)
    echo "fake aws: unsupported command: $*" >&2
    exit 2 ;;
esac
