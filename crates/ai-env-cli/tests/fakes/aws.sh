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
# S5 additions:
#   Endpoint pins: a lambda-core, ec2, ssm, logs, cloudtrail or route53resolver call must carry
#   `--endpoint-url https://<lambda|ec2|ssm|logs|cloudtrail|route53resolver>.eu-central-1.amazonaws.com`
#   (lambda-core's endpoint prefix is lambda), else exit 252. sts: a wrong
#   --endpoint-url is exit 252; a missing one too with FAKE_AWS_PIN_ALL=1 (the
#   S5 operator commands pin sts; doctor and gates do not).
#   FAKE_AWS_ANSWERS=<dir>  generic answers, checked before the built-in ones:
#                          the call's Nth time (N counted per "<service>.<op>" in
#                          <dir>/.count.<service>.<op>) prints <dir>/<service>.<op>.N.json
#                          when it exists, else <dir>/<service>.<op>.json; a sibling
#                          .N.rc / .rc file sets the exit code and .N.stderr / .stderr
#                          is printed to stderr. No file: the built-in answer.
#   FAKE_AWS_SSM_DIR=<dir>  a stateful Parameter Store: parameter /a/b is the file
#                          <dir>/a/b holding its exact value, /a/b.version its
#                          version. put-parameter --name N --value V|file://PATH
#                          [--overwrite] writes it (a value over 4096 bytes is
#                          ValidationException, exit 254; an existing name
#                          without --overwrite is ParameterAlreadyExists);
#                          get-parameter --name N and get-parameters --names N…
#                          answer the real JSON shape (missing names under
#                          InvalidParameters).
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
endpoint=
param_name=
param_value=
param_value_set=0
overwrite=0
names=
in_names=0
prev=
for a in "$@"; do
  if [ "$in_names" = 1 ]; then
    case "$a" in
      --*) in_names=0 ;;
      *) names="$names
$a"; prev=$a; continue ;;
    esac
  fi
  case "$a" in
    --overwrite) overwrite=1 ;;
    --names) in_names=1 ;;
  esac
  case "$prev" in
    --endpoint-url) endpoint=$a ;;
    --name) param_name=$a ;;
    --value) param_value=$a; param_value_set=1 ;;
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
want_endpoint=
case "${1:-}" in
  lambda-core) want_endpoint=https://lambda.eu-central-1.amazonaws.com ;;
  ec2|ssm|logs|cloudtrail|sts|route53resolver) want_endpoint="https://$1.eu-central-1.amazonaws.com" ;;
esac
if [ -n "$want_endpoint" ] && [ "$endpoint" != "$want_endpoint" ]; then
  if [ -n "$endpoint" ] || [ "${1:-}" != sts ] || [ "${FAKE_AWS_PIN_ALL:-0}" = 1 ]; then
    echo "fake aws: $1 calls must carry --endpoint-url $want_endpoint (got '${endpoint}')" >&2
    exit 252
  fi
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
if [ -n "${FAKE_AWS_ANSWERS:-}" ] && [ -n "${2:-}" ]; then
  op="${1:-}.${2:-}"
  case "$op" in
    */*|.*) echo "fake aws: bad operation $op" >&2; exit 252 ;;
  esac
  countf="$FAKE_AWS_ANSWERS/.count.$op"
  n=$(( $(cat "$countf" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$countf"
  base="$FAKE_AWS_ANSWERS/$op"
  if [ -e "$base.$n.json" ] || [ -e "$base.$n.rc" ]; then base="$base.$n"; fi
  if [ -e "$base.json" ] || [ -e "$base.rc" ]; then
    [ -e "$base.stderr" ] && cat "$base.stderr" >&2
    [ -e "$base.json" ] && cat "$base.json"
    exit "$(cat "$base.rc" 2>/dev/null || echo 0)"
  fi
fi

# The exact bytes of file $1 as a JSON string (od + awk: no python, no jq).
json_str() {
  od -An -v -tx1 "$1" | LC_ALL=C awk 'BEGIN { for (i = 0; i < 256; i++) hx[sprintf("%02x", i)] = i; printf "\"" }
    { for (i = 1; i <= NF; i++) { b = hx[$i]
        if ($i == "0a") printf "\\n"; else if ($i == "09") printf "\\t"; else if ($i == "0d") printf "\\r";
        else if ($i == "22") printf "\\\""; else if ($i == "5c") printf "\\\\";
        else if (b < 32) printf "\\u%04x", b; else printf "%c", b } }
    END { printf "\"" }'
}
ssm_file() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *..*|*//*) return 1 ;;
  esac
  printf '%s%s' "$FAKE_AWS_SSM_DIR" "$1"
}
ssm_param_json() {
  f=$(ssm_file "$1") || return 1
  [ -f "$f" ] || return 1
  printf '{"Name": "%s", "Type": "String", "Value": %s, "Version": %s, "DataType": "text"}' "$1" "$(json_str "$f")" "$(cat "$f.version" 2>/dev/null || echo 1)"
}

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
  "ssm put-parameter")
    if [ -z "${FAKE_AWS_SSM_DIR:-}" ]; then echo "fake aws: FAKE_AWS_SSM_DIR is not set" >&2; exit 2; fi
    f=$(ssm_file "$param_name") || { printf '\nAn error occurred (ValidationException) when calling the PutParameter operation: bad name %s\n' "$param_name" >&2; exit 254; }
    if [ "$param_value_set" != 1 ]; then echo "fake aws: put-parameter needs --value" >&2; exit 252; fi
    tmp="$f.new.$$"
    mkdir -p "$(dirname "$f")"
    case "$param_value" in
      file://*) cat "${param_value#file://}" > "$tmp" || exit 255 ;;
      *) printf '%s' "$param_value" > "$tmp" ;;
    esac
    size=$(wc -c < "$tmp" | tr -d ' ')
    if [ "$size" -gt 4096 ]; then
      rm -f "$tmp"
      printf '\nAn error occurred (ValidationException) when calling the PutParameter operation: Standard tier parameters support a maximum parameter value of 4096 characters. Parameter %s has %s.\n' "$param_name" "$size" >&2
      exit 254
    fi
    if [ -f "$f" ] && [ "$overwrite" != 1 ]; then
      rm -f "$tmp"
      printf '\nAn error occurred (ParameterAlreadyExists) when calling the PutParameter operation: The parameter already exists. To overwrite this value, set the overwrite option in the request to true.\n' >&2
      exit 254
    fi
    v=$(( $(cat "$f.version" 2>/dev/null || echo 0) + 1 ))
    mv "$tmp" "$f"
    echo "$v" > "$f.version"
    printf '{\n    "Version": %s,\n    "Tier": "Standard"\n}\n' "$v" ;;
  "ssm get-parameter")
    if [ -z "${FAKE_AWS_SSM_DIR:-}" ]; then echo "fake aws: FAKE_AWS_SSM_DIR is not set" >&2; exit 2; fi
    if doc=$(ssm_param_json "$param_name"); then
      printf '{\n    "Parameter": %s\n}\n' "$doc"
    else
      printf '\nAn error occurred (ParameterNotFound) when calling the GetParameter operation: \n' >&2
      exit 254
    fi ;;
  "ssm get-parameters")
    if [ -z "${FAKE_AWS_SSM_DIR:-}" ]; then echo "fake aws: FAKE_AWS_SSM_DIR is not set" >&2; exit 2; fi
    found=
    missing=
    for n in $(printf '%s\n' "$names" | sed '/^$/d'); do
      if doc=$(ssm_param_json "$n"); then
        found="${found:+$found, }$doc"
      else
        missing="${missing:+$missing, }\"$n\""
      fi
    done
    printf '{\n    "Parameters": [%s],\n    "InvalidParameters": [%s]\n}\n' "$found" "$missing" ;;
  *)
    echo "fake aws: unsupported command: $*" >&2
    exit 2 ;;
esac
