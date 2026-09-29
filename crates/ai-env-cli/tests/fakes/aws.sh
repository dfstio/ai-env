#!/bin/sh
# Fake `aws` CLI for the S3 tests: never talks to AWS. Copied into a temp bin
# dir as `aws`. Every call except `--version` must carry `--region
# eu-central-1` (the house rule for every aws call), else it fails with 252
# like the real CLI's usage errors. Access key ids and secrets are built at
# run time (AKIAFAKE + a 12-digit counter; a repeated 4-character block).
#   aws --version
#   aws iam list-access-keys --user-name U ...   FAKE_AWS_KEYS keys of U
#   aws iam create-access-key --user-name U ...  the create-access-key JSON of
#                                                key number FAKE_AWS_KEYS + 1
#   aws iam delete-access-key ...                no output, exit 0
#   aws sts get-caller-identity ...              user FAKE_AWS_CALLER (rust)
#   aws lambda-microvms get-microvm-image --image-identifier A ...
#                                                the image A in FAKE_AWS_IMAGE_STATE
#                                                (unset: the fake account holds no
#                                                image, ResourceNotFoundException,
#                                                exit 254)
# Environment:
#   FAKE_AWS_LOG    when set, each call's argv is appended here, one line
#   FAKE_AWS_KEYS   access keys the user already has (default 0)
#   FAKE_AWS_FAIL   =1: every call except --version fails like an expired
#                   session (exit 255); =nouser: the iam *-access-key calls
#                   fail like the real CLI for a user that does not exist yet
#                   (NoSuchEntity on stderr, exit 254), other calls work
#   FAKE_AWS_CALLER the user name get-caller-identity reports (default rust)
#   FAKE_AWS_IMAGE_STATE   get-microvm-image's state (CREATED, UPDATED, ...)
#   FAKE_AWS_IMAGE_ACTIVE  its latestActiveImageVersion, a number (unset: null)
#   FAKE_AWS_IMAGE_FAILED  its latestFailedImageVersion, a number (unset: null)
set -u
if [ -n "${FAKE_AWS_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_AWS_LOG"
fi
if [ "${1:-}" = --version ]; then
  echo 'aws-cli/2.0.0 Python/3 fake'
  exit 0
fi
region=
user=
image=
prev=
for a in "$@"; do
  case "$prev" in
    --region) region=$a ;;
    --user-name) user=$a ;;
    --image-identifier) image=$a ;;
  esac
  prev=$a
done
if [ "$region" != eu-central-1 ]; then
  echo 'fake aws: every call must carry --region eu-central-1' >&2
  exit 252
fi
if [ "${FAKE_AWS_FAIL:-0}" = 1 ]; then
  echo 'An error occurred (ExpiredToken) when calling the operation: the fake session expired' >&2
  exit 255
fi
if [ "${FAKE_AWS_FAIL:-0}" = nouser ]; then
  op=
  case "${1:-} ${2:-}" in
    "iam list-access-keys") op=ListAccessKeys ;;
    "iam create-access-key") op=CreateAccessKey ;;
    "iam delete-access-key") op=DeleteAccessKey ;;
  esac
  if [ -n "$op" ]; then
    # The real CLI's shape: a blank line, the service error, exit 254.
    printf '\nAn error occurred (NoSuchEntity) when calling the %s operation: The user with name %s cannot be found.\n' "$op" "$user" >&2
    exit 254
  fi
fi
keys=${FAKE_AWS_KEYS:-0}
key_id() { printf 'AKIAFAKE%012d' "$1"; }
created='2026-09-29T10:00:00+00:00'

case "${1:-} ${2:-}" in
  "iam list-access-keys")
    printf '{\n    "AccessKeyMetadata": ['
    i=1
    sep=
    while [ "$i" -le "$keys" ]; do
      printf '%s\n        {\n            "UserName": "%s",\n            "AccessKeyId": "%s",\n            "Status": "Active",\n            "CreateDate": "%s"\n        }' \
        "$sep" "$user" "$(key_id "$i")" "$created"
      sep=,
      i=$((i + 1))
    done
    printf '\n    ]\n}\n' ;;
  "iam create-access-key")
    secret=$(printf 'Fk9/%.0s' 1 2 3 4 5 6 7 8 9 10)
    printf '{\n    "AccessKey": {\n        "UserName": "%s",\n        "AccessKeyId": "%s",\n        "Status": "Active",\n        "SecretAccessKey": "%s",\n        "CreateDate": "%s"\n    }\n}\n' \
      "$user" "$(key_id $((keys + 1)))" "$secret" "$created" ;;
  "iam delete-access-key") ;;
  "sts get-caller-identity")
    printf '{\n    "UserId": "AIDAFAKEFAKEFAKEFAKE",\n    "Account": "123456789012",\n    "Arn": "arn:aws:iam::123456789012:user/%s"\n}\n' "${FAKE_AWS_CALLER:-rust}" ;;
  "lambda-microvms get-microvm-image")
    if [ -z "${FAKE_AWS_IMAGE_STATE:-}" ]; then
      printf '\nAn error occurred (ResourceNotFoundException) when calling the GetMicrovmImage operation: Image %s not found\n' "$image" >&2
      exit 254
    fi
    printf '{\n    "imageArn": "%s",\n    "imageName": "%s",\n    "state": "%s",\n    "latestActiveImageVersion": %s,\n    "latestFailedImageVersion": %s\n}\n' \
      "$image" "${image##*:}" "$FAKE_AWS_IMAGE_STATE" "${FAKE_AWS_IMAGE_ACTIVE:-null}" "${FAKE_AWS_IMAGE_FAILED:-null}" ;;
  *)
    echo "fake aws: unsupported command: $*" >&2
    exit 2 ;;
esac
