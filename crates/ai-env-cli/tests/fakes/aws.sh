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
#   aws sts get-caller-identity ...              the caller: the key's user, else
#                                                FAKE_AWS_CALLER (rust); see S8 below
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
#   FAKE_AWS_CALLER the caller without a key (default user rust; S8 forms below)
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
#                          InvalidParameters); get-parameters takes
#                          --with-decryption (S13: the relay's reload unit)
#                          and answers the same.
#                          S13 (M, §Q.8 F5): a put naming --type keeps it in
#                          /a/b.type; an overwrite naming another type than
#                          that file's is HierarchyTypeMismatchException, exit
#                          254 (the real Parameter Store never changes a
#                          parameter's type), the value untouched. A put whose
#                          --value is file:///dev/stdin while
#                          AWS_CLI_AUTO_PROMPT is on fails, exit 255: the real
#                          CLI's prompt would read its keystrokes from that
#                          stdin (no other call models the prompt).
# S13 (the relay's reload unit, infra/relay/reload.py):
#   aws s3api get-object --bucket B --key K OUTFILE   FAKE_AWS_S3_DIR/B/K copied to
#                          OUTFILE (the last argument) with the real answer's
#                          JSON; missing: NoSuchKey, exit 254. s3api calls are
#                          pinned as sts: --endpoint-url https://s3.eu-central-1.amazonaws.com,
#                          a wrong one refused (252), a missing one too with
#                          FAKE_AWS_PIN_ALL=1.
# S8 operators (plans/s8-operators-contracts.md §10.1, §10.2). A fake key id is
# AKIAFAKE and 12 digits; its last four are its tail (9001 the deployer, 9002
# ops, 9003 runtime).
#   aws sts get-caller-identity ...   with AWS_ACCESS_KEY_ID set: a session
#       token beside it (AWS_SESSION_TOKEN, AWS_SECURITY_TOKEN) is
#       InvalidClientTokenId, an AWS_SECRET_ACCESS_KEY that is not 40
#       characters SignatureDoesNotMatch, a tail FAKE_AWS_KEY_USERS does not
#       list InvalidClientTokenId (each exit 254); a listed tail answers as its
#       user. Without a key: FAKE_AWS_CALLER. FAKE_AWS_ANSWERS still answers first.
#   aws iam simulate-principal-policy --policy-source-arn P --action-names A...
#       [--resource-arns R...]   a result per action and resource (no
#       --resource-arns: the resource *): allowed when FAKE_AWS_SIM_ALLOW lists
#       the pair, else implicitDeny; a P ending in :root is InvalidInput (254)
#   aws iam get-account-summary   its SummaryMap, AccountAccessKeysPresent
#       FAKE_AWS_ROOT_KEYS (default 0)
#   aws ssm send-command ...   a guard, after FAKE_AWS_FAIL(_OP) and before
#       FAKE_AWS_ANSWERS: only the documents ai-env-proxy-reload, -status and
#       -patch (another one: AccessDeniedException), each with
#       --document-version $DEFAULT (else InvalidDocumentVersion) and
#       --parameters exactly {"mode":["apply"]} or {"mode":["if-changed"]} for
#       reload, none for status and patch (else InvalidParameters), each exit
#       254; no --document-name: the usage error (252)
#   AWS_PROFILE set with AWS_CONFIG_FILE=/dev/null: every call but --version
#       fails like the real CLI (the profile cannot be found, exit 255)
#   FAKE_AWS_KEY_USERS  space-separated TAIL:USER or TAIL:USER@ACCOUNT (USER
#                       root: the account root; ACCOUNT default 123456789012);
#                       default 9001:ai-env-deployer 9002:ai-env-ops
#                       9003:ai-env-runtime
#   FAKE_AWS_CALLER     USER or USER@ACCOUNT; root (or root@ACCOUNT): the
#                       account root; none: no credentials ("Unable to locate
#                       credentials", exit 253)
#   FAKE_AWS_SIM_ALLOW  space-separated USER|ACTION|SUFFIX: USER is the last
#                       path segment of --policy-source-arn, the resource ARN
#                       ends with SUFFIX (* matches only the resource *)
#   FAKE_AWS_SIM_SHAPE  nested: one result per action (EvalResourceName *,
#                       allowed only when every resource is) with
#                       ResourceSpecificResults; else one per action and
#                       resource, in argument order
#   FAKE_AWS_ENV_LOG    one line per call but --version: "<service> <operation>
#                       | <names> | <pins>". The names set among
#                       AI_ENV_BRIDGE_AS, AWS_ACCESS_KEY_ID,
#                       AWS_SECRET_ACCESS_KEY, the 14 credential selectors of
#                       src/bridge/identity.rs (in its order), then every
#                       AWS_CONTAINER_* and AWS_ENDPOINT_URL* name, sorted; each
#                       pin set as NAME=<value> when the value is /dev/null,
#                       true, eu-central-1 or empty, else NAME=other; "-" for
#                       none. No other value is ever logged.
set -u
if [ -n "${FAKE_AWS_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_AWS_LOG"
fi
if [ "${1:-}" = --version ]; then
  echo 'aws-cli/2.0.0 Python/3 fake'
  exit 0
fi
if [ -n "${FAKE_AWS_ENV_LOG:-}" ]; then
  # Names only; a pin's value only when it is one ai-env sets.
  env_names=
  for env_n in AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_PROFILE AWS_DEFAULT_PROFILE AWS_SESSION_TOKEN \
    AWS_SECURITY_TOKEN AWS_CREDENTIAL_EXPIRATION AWS_ACCESS_KEY AWS_SECRET_KEY AWS_ROLE_ARN AWS_ROLE_SESSION_NAME \
    AWS_WEB_IDENTITY_TOKEN_FILE AWS_ACCOUNT_ID AWS_SDK_LOAD_CONFIG AWS_EC2_METADATA_SERVICE_ENDPOINT \
    AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE; do
    eval "env_set=\${$env_n+x}"
    test -z "$env_set" || env_names="${env_names:+$env_names }$env_n"
  done
  for env_n in $(env | sed -n 's/^\(AWS_CONTAINER_[A-Za-z0-9_]*\)=.*/\1/p; s/^\(AWS_ENDPOINT_URL[A-Za-z0-9_]*\)=.*/\1/p' | LC_ALL=C sort -u); do
    env_names="${env_names:+$env_names }$env_n"
  done
  env_pins=
  for env_n in AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_EC2_METADATA_DISABLED AWS_IGNORE_CONFIGURED_ENDPOINT_URLS \
    AWS_REGION AWS_DEFAULT_REGION AWS_PAGER; do
    eval "env_set=\${$env_n+x} env_v=\${$env_n-}"
    if [ -n "$env_set" ]; then
      case "$env_v" in
        /dev/null|true|eu-central-1|'') ;;
        *) env_v=other ;;
      esac
      env_pins="${env_pins:+$env_pins }$env_n=$env_v"
    fi
  done
  printf '%s %s | %s | %s\n' "${1:-}" "${2:-}" "${env_names:--}" "${env_pins:--}" >> "$FAKE_AWS_ENV_LOG"
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
param_type=
overwrite=0
names=
actions=
resources=
source_arn=
doc_name=
doc_set=0
doc_version=
params=
params_set=0
s3_bucket=
s3_key=
multi=
prev=
for a in "$@"; do
  # A multi-value option (--names, --action-names, --resource-arns) takes the words up to the next --option.
  if [ -n "$multi" ]; then
    case "$a" in
      --*) multi= ;;
      *)
        case "$multi" in
          names) names="$names
$a" ;;
          actions) actions="$actions
$a" ;;
          *) resources="$resources
$a" ;;
        esac
        prev=$a; continue ;;
    esac
  fi
  case "$a" in
    --overwrite) overwrite=1 ;;
    --names) multi=names ;;
    --action-names) multi=actions ;;
    --resource-arns) multi=resources ;;
  esac
  case "$prev" in
    --endpoint-url) endpoint=$a ;;
    --name) param_name=$a ;;
    --value) param_value=$a; param_value_set=1 ;;
    --type) param_type=$a ;;
    --region) region=$a ;;
    --user-name) user=$a ;;
    --image-identifier) image=$a ;;
    --service-code) service=$a ;;
    --quota-code) quota=$a ;;
    --next-token) next_token=$a ;;
    --channel) channel=$a ;;
    --log-group-name-pattern) pattern=$a ;;
    --log-group-class) log_class=$a ;;
    --policy-source-arn) source_arn=$a ;;
    --document-name) doc_name=$a; doc_set=1 ;;
    --document-version) doc_version=$a ;;
    --parameters) params=$a; params_set=1 ;;
    --bucket) s3_bucket=$a ;;
    --key) s3_key=$a ;;
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
  s3api) want_endpoint=https://s3.eu-central-1.amazonaws.com ;;
esac
if [ -n "$want_endpoint" ] && [ "$endpoint" != "$want_endpoint" ]; then
  if [ -n "$endpoint" ] || { [ "${1:-}" != sts ] && [ "${1:-}" != s3api ]; } || [ "${FAKE_AWS_PIN_ALL:-0}" = 1 ]; then
    echo "fake aws: $1 calls must carry --endpoint-url $want_endpoint (got '${endpoint}')" >&2
    exit 252
  fi
fi
# A profile with the config file pinned to /dev/null (ai-env as deployer|ops leaves AWS_PROFILE out): the real
# CLI fails before any request.
if [ -n "${AWS_PROFILE:-}" ] && [ "${AWS_CONFIG_FILE:-}" = /dev/null ]; then
  printf '\nThe config profile (%s) could not be found\n' "$AWS_PROFILE" >&2
  exit 255
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

# key_user <tail>: FAKE_AWS_KEY_USERS' entry for a key id's last four characters ("USER" or "USER@ACCOUNT"),
# else nothing and status 1 (matched as a string: no word splitting, no globbing).
key_user() {
  ku=" ${FAKE_AWS_KEY_USERS:-9001:ai-env-deployer 9002:ai-env-ops 9003:ai-env-runtime} "
  case "$ku" in
    *" $1:"*) ku=${ku#*" $1:"}; printf '%s' "${ku%% *}"; return 0 ;;
  esac
  return 1
}
# caller <operation>: who signs this call, as the CLI and AWS see it: sets caller_arn, caller_acct and caller_uid,
# or prints their refusal (naming <operation>) and exits as they do.
caller() {
  if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
    if [ -n "${AWS_SESSION_TOKEN:-}${AWS_SECURITY_TOKEN:-}" ]; then
      printf '\nAn error occurred (InvalidClientTokenId) when calling the %s operation: The security token included in the request is invalid.\n' "$1" >&2
      exit 254
    fi
    caller_secret=${AWS_SECRET_ACCESS_KEY:-}
    if [ "${#caller_secret}" -ne 40 ]; then
      printf '\nAn error occurred (SignatureDoesNotMatch) when calling the %s operation: The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.\n' "$1" >&2
      exit 254
    fi
    caller_secret=
    caller_tail=${AWS_ACCESS_KEY_ID#"${AWS_ACCESS_KEY_ID%????}"}
    if ! caller_who=$(key_user "$caller_tail"); then
      printf '\nAn error occurred (InvalidClientTokenId) when calling the %s operation: The security token included in the request is invalid.\n' "$1" >&2
      exit 254
    fi
  else
    caller_who=${FAKE_AWS_CALLER:-rust}
    if [ "$caller_who" = none ]; then
      echo 'Unable to locate credentials. You can configure credentials by running "aws configure".' >&2
      exit 253
    fi
  fi
  caller_acct=123456789012
  case "$caller_who" in
    *@*) caller_acct=${caller_who#*@}; caller_who=${caller_who%%@*} ;;
  esac
  if [ "$caller_who" = root ]; then
    caller_arn="arn:aws:iam::$caller_acct:root"
    caller_uid=$caller_acct
  else
    caller_arn="arn:aws:iam::$caller_acct:user/$caller_who"
    caller_uid=AIDAFAKEFAKEFAKEFAKE
  fi
}
# sim_allowed <user> <action> <resource>: FAKE_AWS_SIM_ALLOW lists the pair.
sim_allowed() {
  printf '%s\n' "${FAKE_AWS_SIM_ALLOW:-}" | tr ' ' '\n' | {
    while IFS= read -r sim_e; do
      case "$sim_e" in
        "$1|$2|"*) sim_s=${sim_e#"$1|$2|"} ;;
        *) continue ;;
      esac
      if [ "$sim_s" = '*' ]; then
        [ "$3" != '*' ] || exit 0
      else
        case "$3" in *"$sim_s") exit 0 ;; esac
      fi
    done
    exit 1
  }
}

# The send-command guard: the CLI sends only the three fixed proxy documents, at $DEFAULT, with the reload
# document's one parameter; an accepted call goes on to FAKE_AWS_ANSWERS.
if [ "${1:-} ${2:-}" = "ssm send-command" ]; then
  if [ "$doc_set" != 1 ]; then
    echo 'aws: error: the following arguments are required: --document-name' >&2
    exit 252
  fi
  case "$doc_name" in
    ai-env-proxy-reload|ai-env-proxy-status|ai-env-proxy-patch)
      if [ "$doc_version" != '$DEFAULT' ]; then
        printf '\nAn error occurred (InvalidDocumentVersion) when calling the SendCommand operation: the fake takes %s only at --document-version $DEFAULT\n' "$doc_name" >&2
        exit 254
      fi
      case "$doc_name:$params_set:$params" in
        'ai-env-proxy-reload:1:{"mode":["apply"]}'|'ai-env-proxy-reload:1:{"mode":["if-changed"]}'|ai-env-proxy-status:0:|ai-env-proxy-patch:0:) ;;
        ai-env-proxy-reload:*)
          printf '\nAn error occurred (InvalidParameters) when calling the SendCommand operation: %s takes exactly --parameters {"mode":["apply"]} or {"mode":["if-changed"]}\n' "$doc_name" >&2
          exit 254 ;;
        *)
          printf '\nAn error occurred (InvalidParameters) when calling the SendCommand operation: %s takes no --parameters\n' "$doc_name" >&2
          exit 254 ;;
      esac ;;
    *)
      caller SendCommand
      doc_acct=$caller_acct
      case "$doc_name" in AWS-*) doc_acct= ;; esac
      printf '\nAn error occurred (AccessDeniedException) when calling the SendCommand operation: User: %s is not authorized to perform: ssm:SendCommand on resource: arn:aws:ssm:eu-central-1:%s:document/%s because no identity-based policy allows the ssm:SendCommand action\n' "$caller_arn" "$doc_acct" "$doc_name" >&2
      exit 254 ;;
  esac
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
  "iam simulate-principal-policy")
    if [ -z "$source_arn" ] || [ -z "$actions" ]; then
      echo 'aws: error: the following arguments are required: --policy-source-arn, --action-names' >&2
      exit 252
    fi
    case "$source_arn" in
      *:root)
        printf '\nAn error occurred (InvalidInput) when calling the SimulatePrincipalPolicy operation: Invalid Entity Arn: %s does not clearly define entity type and name.\n' "$source_arn" >&2
        exit 254 ;;
    esac
    sim_user=${source_arn##*/}
    test -n "$resources" || resources='*'
    # One word per line, never globbed (a resource may be *).
    sim_ifs=$IFS
    IFS='
'
    set -f
    printf '{\n    "EvaluationResults": ['
    sep=
    for sim_a in $actions; do
      if [ "${FAKE_AWS_SIM_SHAPE:-}" = nested ]; then
        sim_d=allowed
        for sim_r in $resources; do
          sim_allowed "$sim_user" "$sim_a" "$sim_r" || sim_d=implicitDeny
        done
        printf '%s\n        {\n            "EvalActionName": "%s",\n            "EvalResourceName": "*",\n            "EvalDecision": "%s",\n            "MatchedStatements": [],\n            "MissingContextValues": [],\n            "ResourceSpecificResults": [' \
          "$sep" "$sim_a" "$sim_d"
        rsep=
        for sim_r in $resources; do
          if sim_allowed "$sim_user" "$sim_a" "$sim_r"; then sim_d=allowed; else sim_d=implicitDeny; fi
          printf '%s\n                {\n                    "EvalResourceName": "%s",\n                    "EvalResourceDecision": "%s"\n                }' "$rsep" "$sim_r" "$sim_d"
          rsep=,
        done
        printf '\n            ]\n        }'
      else
        for sim_r in $resources; do
          if sim_allowed "$sim_user" "$sim_a" "$sim_r"; then sim_d=allowed; else sim_d=implicitDeny; fi
          printf '%s\n        {\n            "EvalActionName": "%s",\n            "EvalResourceName": "%s",\n            "EvalDecision": "%s",\n            "MatchedStatements": [],\n            "MissingContextValues": []\n        }' \
            "$sep" "$sim_a" "$sim_r" "$sim_d"
          sep=,
        done
      fi
      sep=,
    done
    set +f
    IFS=$sim_ifs
    printf '\n    ]\n}\n' ;;
  "iam get-account-summary")
    case "${FAKE_AWS_ROOT_KEYS:-0}" in
      *[!0-9]*) echo "fake aws: FAKE_AWS_ROOT_KEYS is not a number" >&2; exit 2 ;;
    esac
    printf '{\n    "SummaryMap": {\n        "AccountAccessKeysPresent": %s,\n        "AccountMFAEnabled": 1,\n        "Users": 3\n    }\n}\n' "${FAKE_AWS_ROOT_KEYS:-0}" ;;
  "sts get-caller-identity")
    caller GetCallerIdentity
    printf '{\n    "UserId": "%s",\n    "Account": "%s",\n    "Arn": "%s"\n}\n' "$caller_uid" "$caller_acct" "$caller_arn" ;;
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
    if [ "$param_value" = file:///dev/stdin ]; then
      case "${AWS_CLI_AUTO_PROMPT:-}" in
        [Oo][Nn]) echo "fake aws: AWS_CLI_AUTO_PROMPT is on: the prompt would read its keystrokes from stdin, which holds the value" >&2; exit 255 ;;
      esac
    fi
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
    if [ -f "$f" ] && [ -n "$param_type" ] && [ -f "$f.type" ] && [ "$(cat "$f.type")" != "$param_type" ]; then
      rm -f "$tmp"
      printf '\nAn error occurred (HierarchyTypeMismatchException) when calling the PutParameter operation: %s is a %s, and a parameter type cannot be changed.\n' "$param_name" "$(cat "$f.type")" >&2
      exit 254
    fi
    v=$(( $(cat "$f.version" 2>/dev/null || echo 0) + 1 ))
    mv "$tmp" "$f"
    echo "$v" > "$f.version"
    if [ -n "$param_type" ]; then printf '%s\n' "$param_type" > "$f.type"; fi
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
  "s3api get-object")
    if [ -z "${FAKE_AWS_S3_DIR:-}" ]; then echo "fake aws: FAKE_AWS_S3_DIR is not set" >&2; exit 2; fi
    for s3_out; do :; done
    case "$s3_bucket/$s3_key" in
      /*|*/|*..*|*//*) printf '\nAn error occurred (InvalidRequest) when calling the GetObject operation: bad bucket or key\n' >&2; exit 254 ;;
    esac
    case "$s3_out" in
      ''|--*) echo 'aws: error: the following arguments are required: outfile' >&2; exit 252 ;;
    esac
    s3_file="$FAKE_AWS_S3_DIR/$s3_bucket/$s3_key"
    if [ ! -f "$s3_file" ]; then
      printf '\nAn error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.\n' >&2
      exit 254
    fi
    cat "$s3_file" > "$s3_out" || exit 255
    printf '{\n    "AcceptRanges": "bytes",\n    "ContentLength": %s,\n    "ContentType": "application/octet-stream"\n}\n' "$(wc -c < "$s3_file" | tr -d ' ')" ;;
  *)
    echo "fake aws: unsupported command: $*" >&2
    exit 2 ;;
esac
