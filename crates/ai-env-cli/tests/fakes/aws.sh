#!/bin/sh
# Fake `aws` CLI for the S3 and S4 tests: never talks to AWS. Copied into a
# temp bin dir as `aws`. Every call except `--version` must carry `--region
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
#   aws service-quotas get-service-quota --service-code lambda --quota-code
#       L-CD1C0CC4 ...                           the quota JSON, Value
#                                                FAKE_AWS_QUOTA_GB (any other
#                                                code: NoSuchResourceException,
#                                                exit 254)
#   aws cloudtrail describe-trails ...           the contents of FAKE_AWS_TRAILS_FILE
#                                                (unset: {"trailList": []})
#   aws cloudtrail get-event-selectors ...       the contents of FAKE_AWS_SELECTORS_FILE
#                                                (unset: management events only)
#   aws cloudtrail list-channels ...             the contents of FAKE_AWS_CHANNELS_FILE, or of
#                                                FAKE_AWS_CHANNELS_FILE_2 when --next-token is
#                                                given (it must equal FAKE_AWS_CHANNELS_TOKEN,
#                                                else InvalidNextTokenException, exit 254)
#                                                (unset: {"Channels": []})
#                                                FAKE_AWS_CHANNELS_ENDLESS=1: every page is empty
#                                                with a new NextToken (the page bound)
#   aws cloudtrail get-channel --channel ARN ... FAKE_AWS_CHANNEL_DIR/<last ARN segment>.json
#                                                (missing, or --channel not an ARN:
#                                                ChannelNotFoundException, exit 254)
#   aws logs describe-log-groups --log-group-name-pattern cloudtrail [--log-group-class C] ...
#                                                with C: FAKE_AWS_LOG_GROUPS_<C>_FILE; without:
#                                                FAKE_AWS_LOG_GROUPS_FILE (names only, as the
#                                                real pattern answer); unset: {"logGroups": []};
#                                                any other pattern: InvalidParameterException
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
#   FAKE_AWS_QUOTA_GB      the MicroVM memory quota's Value in Gigabytes, a
#                          number (default 400.0, the AWS default)
#   FAKE_AWS_TRAILS_FILE, FAKE_AWS_SELECTORS_FILE, FAKE_AWS_CHANNELS_FILE[_2],
#   FAKE_AWS_CHANNELS_TOKEN, FAKE_AWS_CHANNEL_DIR, FAKE_AWS_LOG_GROUPS_FILE
#                          CloudTrail and CloudWatch Logs JSON documents (see above)
#   FAKE_AWS_FAIL_OP       "<service> <operation>" (e.g. "cloudtrail describe-trails"):
#                          that call fails with AccessDeniedException, exit 254
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
service=
quota=
next_token=
channel=
pattern=
log_class=
prev=
for a in "$@"; do
  case "$prev" in
    --region) region=$a ;;
    --user-name) user=$a ;;
    --image-identifier) image=$a ;;
    --service-code) service=$a ;;
    --quota-code) quota=$a ;;
    --next-token) next_token=$a ;;
    --channel) channel=$a ;;
    --log-group-name-pattern) pattern=$a ;;
    --log-group-class) log_class=$a ;;
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
if [ -n "${FAKE_AWS_FAIL_OP:-}" ] && [ "${1:-} ${2:-}" = "$FAKE_AWS_FAIL_OP" ]; then
  printf '\nAn error occurred (AccessDeniedException) when calling the %s operation: fake denial\n' "${2:-}" >&2
  exit 254
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
  "service-quotas get-service-quota")
    if [ "$service" != lambda ] || [ "$quota" != L-CD1C0CC4 ]; then
      printf '\nAn error occurred (NoSuchResourceException) when calling the GetServiceQuota operation: The request failed because the specified quota %s does not exist for service %s.\n' "$quota" "$service" >&2
      exit 254
    fi
    printf '{\n    "Quota": {\n        "ServiceCode": "lambda",\n        "ServiceName": "AWS Lambda",\n        "QuotaArn": "arn:aws:servicequotas:%s:123456789012:lambda/%s",\n        "QuotaCode": "%s",\n        "QuotaName": "Max allocated ARM_64 MicroVM memory",\n        "Value": %s,\n        "Unit": "None",\n        "Adjustable": true,\n        "GlobalQuota": false\n    }\n}\n' \
      "$region" "$quota" "$quota" "${FAKE_AWS_QUOTA_GB:-400.0}" ;;
  "cloudtrail describe-trails")
    if [ -n "${FAKE_AWS_TRAILS_FILE:-}" ]; then cat "$FAKE_AWS_TRAILS_FILE"; else printf '{\n    "trailList": []\n}\n'; fi ;;
  "cloudtrail get-event-selectors")
    if [ -n "${FAKE_AWS_SELECTORS_FILE:-}" ]; then
      cat "$FAKE_AWS_SELECTORS_FILE"
    else
      printf '{\n    "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": true, "DataResources": []}]\n}\n'
    fi ;;
  "cloudtrail list-channels")
    if [ "${FAKE_AWS_CHANNELS_ENDLESS:-0}" = 1 ]; then
      printf '{\n    "Channels": [],\n    "NextToken": "%sx"\n}\n' "$next_token"
    elif [ -n "$next_token" ]; then
      if [ "$next_token" != "${FAKE_AWS_CHANNELS_TOKEN:-}" ] || [ -z "${FAKE_AWS_CHANNELS_FILE_2:-}" ]; then
        printf '\nAn error occurred (InvalidNextTokenException) when calling the ListChannels operation: bad token %s\n' "$next_token" >&2
        exit 254
      fi
      cat "$FAKE_AWS_CHANNELS_FILE_2"
    elif [ -n "${FAKE_AWS_CHANNELS_FILE:-}" ]; then
      cat "$FAKE_AWS_CHANNELS_FILE"
    else
      printf '{\n    "Channels": []\n}\n'
    fi ;;
  "cloudtrail get-channel")
    doc="${FAKE_AWS_CHANNEL_DIR:-/nonexistent}/${channel##*/}.json"
    if [ "${channel#arn:aws:cloudtrail:}" != "$channel" ] && [ -f "$doc" ]; then
      cat "$doc"
    else
      printf '\nAn error occurred (ChannelNotFoundException) when calling the GetChannel operation: %s\n' "$channel" >&2
      exit 254
    fi ;;
  "logs describe-log-groups")
    if [ "$pattern" != cloudtrail ]; then
      printf '\nAn error occurred (InvalidParameterException) when calling the DescribeLogGroups operation: fake expects --log-group-name-pattern cloudtrail, got "%s"\n' "$pattern" >&2
      exit 254
    fi
    case "$log_class" in
      *[!A-Z_]*) echo "fake aws: bad --log-group-class $log_class" >&2; exit 252 ;;
    esac
    if [ -n "$log_class" ]; then
      eval "file=\${FAKE_AWS_LOG_GROUPS_${log_class}_FILE:-}"
    else
      file=${FAKE_AWS_LOG_GROUPS_FILE:-}
    fi
    if [ -n "$file" ]; then cat "$file"; else printf '{\n    "logGroups": []\n}\n'; fi ;;
  *)
    echo "fake aws: unsupported command: $*" >&2
    exit 2 ;;
esac
