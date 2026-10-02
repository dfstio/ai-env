#!/bin/sh
# Stateful fake `aws` for the recipe tests (tests/infra/image.rs: runtime-key,
# ops.sh wait, the S5 egress ops, s3-preflight P13-P16): never talks to AWS.
# Copied into a temp bin dir as `aws`. The
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
#   lambda-microvms list-microvm-image-versions   the lines "<version> <status>" of
#       $S/image/versions as items (state SUCCESSFUL); no file: {"items": []}
#   lambda-microvms list-microvms   the lines "<id> <image version> <state>" of
#       $S/vms as items (JSON only: no --query)
#   lambda-microvms get-microvm-image-version --image-version V   {"imageVersion": V, "codeArtifact":
#       {"uri": <$S/image/uri>}} (no uri file: no codeArtifact)
# S5 (the egress ops of infra/scripts/ops.sh and the s3-preflight rows P13-P16).
# A lambda-core, ec2, ssm or logs call must carry `--endpoint-url
# https://<lambda|ec2|ssm|logs>.eu-central-1.amazonaws.com` (lambda-core's
# endpoint prefix is lambda), else exit 252, as tests/fakes/aws.sh pins them.
# A network connector is the directory $S/connectors/<name>, holding:
#       states        the states its get-network-connector calls report, one
#                     word per call, the last one sticking (default ACTIVE); a
#                     listing shows the current (first) word without using it
#       reason, reason_code   its StateReason / StateReasonCode (optional)
#       subnet, sg, role      its configuration (defaults: the golden fixture's)
#       id            its Id (default nc-<cksum of the name>)
#       delete-states when present, a delete keeps the connector with these
#                     states (e.g. "DELETING DELETE_FAILED") instead of removing it
#       hold, peeked  while `hold` exists without `peeked`, it reports PENDING
#                     and its states do not advance (tests/fakes/ai-env.sh
#                     writes `peeked`)
#       delete-refusals   N: the next N deletes are refused (ResourceConflictException,
#                     254), as for a PENDING connector or one a VM still holds
#   lambda-core get-network-connector --identifier <name|Id|ARN[:N]>
#       the unwrapped JSON (ResourceNotFoundException, 254)
#   lambda-core list-network-connectors   {"NetworkConnectors": [...]} of all
#   lambda-core create-network-connector --name N --configuration J --operator-role R
#       creates $S/connectors/N (its states: $S/create-states, default
#       "PENDING ACTIVE"; its delete-refusals: $S/create-delete-refusals;
#       with $S/create-hold it is held: PENDING, its states not advancing,
#       until the ai-env stand-in's `lab run connector-pending` of it ends;
#       the raw configuration kept in `configuration`);
#       FAKE_AWS_CREATE_CONNECTOR=fail: nothing created, exit 254
#   lambda-core delete-network-connector --identifier X   removes it and appends
#       its name to $S/deleted; FAKE_AWS_DELETE_CONNECTOR=fail: exit 254
#   ec2 describe-instances --instance-ids I   the proxy $S/proxy/{id,state}
#       (default id i-0123456789abcdef0; no state file: InvalidInstanceID.NotFound)
#   ec2 describe-network-interfaces [--include-managed-resources] --filters
#       Name=subnet-id,Values=S   the lines "<eni> <ip> <sg> <subnet> [managed]"
#       of $S/enis in that subnet; a managed one only with the flag (as AWS)
#   ec2 describe-vpc-block-public-access-options [--query
#       VpcBlockPublicAccessOptions.InternetGatewayBlockMode --output text]
#       the mode in $S/bpa (default off)
#   ec2 describe-vpcs [--filters Name=tag:Project,Values=P] --query
#       'Vpcs[].[VpcId,CidrBlock]' --output text   the lines "<id> <cidr> [project]"
#       of $S/vpcs (with the filter only those of project P), id and cidr tab-separated
#   ec2 describe-vpc-block-public-access-exclusions --query
#       'VpcBlockPublicAccessExclusions[].[ResourceArn,InternetGatewayExclusionMode,State]'
#       --output text   the lines "<arn> <mode> <state>" of $S/bpa-exclusions
#   service-quotas get-service-quota --service-code vpc --quota-code L-F678F1CE
#       --query Quota.Value --output text   $S/vpc-quota (default 5.0)
#   iam get-role --role-name AWSServiceRoleForLambda --query Role.Arn --output text
#       its ARN when $S/slr exists, else NoSuchEntity (254)
#   logs tail <group> ...      two hostname-only squid lines
#   FAKE_AWS_FAIL_OP="<service> <operation>"   that call fails (AccessDenied, 254)
#   FAKE_AWS_NO_LAMBDA_CORE=1  lambda-core is an invalid choice (an aws CLI
#       older than the service: the usage error, 252)
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
endpoint=
ident=
cname=
config=
role=
role_name=
instance=
filters=
include_managed=0
service=
quota=
image_version=
prev=
for a in "$@"; do
  case "$a" in
    --include-managed-resources) include_managed=1 ;;
  esac
  case "$prev" in
    --region) region=$a ;;
    --user-name) user=$a ;;
    --access-key-id) key=$a ;;
    --query) query=$a ;;
    --name-filter) name=$a ;;
    --endpoint-url) endpoint=$a ;;
    --identifier) ident=$a ;;
    --name) cname=$a ;;
    --configuration) config=$a ;;
    --operator-role) role=$a ;;
    --role-name) role_name=$a ;;
    --instance-ids) instance=$a ;;
    --filters) filters=$a ;;
    --service-code) service=$a ;;
    --quota-code) quota=$a ;;
    --image-version) image_version=$a ;;
  esac
  prev=$a
done
if [ "$region" != eu-central-1 ]; then
  echo 'fake aws: every call must carry --region eu-central-1' >&2
  exit 252
fi
if [ "${1:-}" = lambda-core ] && [ "${FAKE_AWS_NO_LAMBDA_CORE:-0}" = 1 ]; then
  printf '\nusage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]\naws: error: argument command: Invalid choice, valid choices are:\n\naccessanalyzer                           | account\n' >&2
  exit 252
fi
want_endpoint=
case "${1:-}" in
  lambda-core) want_endpoint=https://lambda.eu-central-1.amazonaws.com ;;
  ec2|ssm|logs) want_endpoint="https://$1.eu-central-1.amazonaws.com" ;;
esac
if [ -n "$want_endpoint" ] && [ "$endpoint" != "$want_endpoint" ]; then
  echo "fake aws: $1 calls must carry --endpoint-url $want_endpoint (got '${endpoint}')" >&2
  exit 252
fi
touch "$S/keys"
acct=123456789012
key_id() { printf 'AKIAFAKE%012d' "$1"; }
err() { printf '\nAn error occurred (%s) when calling the %s operation: %s\n' "$1" "$2" "$3" >&2; exit "${4:-254}"; }
if [ -n "${FAKE_AWS_FAIL_OP:-}" ] && [ "${1:-} ${2:-}" = "$FAKE_AWS_FAIL_OP" ]; then
  err AccessDeniedException "${2:-}" "fake denial"
fi
unsupported_query() { echo "fake aws: unsupported --query for ${1:-} ${2:-}: $query" >&2; exit 2; }

# ---- network connectors ($S/connectors/<name>) ----
conn_id() {
  if [ -s "$1/id" ]; then cat "$1/id"; else printf 'nc-%s' "$(printf '%s' "${1##*/}" | cksum | cut -d' ' -f1)"; fi
}
conn_arn() { printf 'arn:aws:lambda:eu-central-1:%s:network-connector:%s' "$acct" "${1##*/}"; }
# conn_dir <identifier>: the connector's directory (its name, Id or ARN, with or without a :N version).
conn_dir() {
  for d in "$S"/connectors/*; do
    [ -d "$d" ] || continue
    a=$(conn_arn "$d")
    case "$1" in
      "${d##*/}"|"$(conn_id "$d")"|"$a"|"$a":[0-9]*) printf '%s' "$d"; return 0 ;;
    esac
  done
  return 1
}
# held <dir>: the connector has `hold` but not yet `peeked` (the ai-env stand-in writes it when its `lab run
# connector-pending` of this connector ends): it reports PENDING and its states do not advance.
held() { [ -f "$1/hold" ] && [ ! -f "$1/peeked" ]; }
cur_state() {
  if held "$1"; then echo PENDING; return 0; fi
  set -- $(cat "$1/states" 2>/dev/null)
  echo "${1:-ACTIVE}"
}
pop_state() {
  d=$1
  if held "$d"; then echo PENDING; return 0; fi
  set -- $(cat "$d/states" 2>/dev/null)
  s=${1:-ACTIVE}
  if [ $# -gt 1 ]; then
    shift
    echo "$*" > "$d/states"
  fi
  echo "$s"
}
file_or() { if [ -s "$1" ]; then cat "$1"; else printf '%s' "$2"; fi; }
conn_json() {
  printf '{\n    "Arn": "%s",\n    "Name": "%s",\n    "Id": "%s",\n    "Version": 1,\n' "$(conn_arn "$1")" "${1##*/}" "$(conn_id "$1")"
  printf '    "Configuration": {\n        "VpcEgressConfiguration": {\n            "SubnetIds": [\n                "%s"\n            ],\n            "SecurityGroupIds": [\n                "%s"\n            ],\n            "NetworkProtocol": "IPv4",\n            "AssociatedComputeResourceTypes": [\n                "MicroVm"\n            ]\n        }\n    },\n' \
    "$(file_or "$1/subnet" subnet-0aaa1111bbbb2222c)" "$(file_or "$1/sg" sg-0ddd3333eeee4444f)"
  printf '    "OperatorRole": "%s",\n    "State": "%s",\n' "$(file_or "$1/role" "arn:aws:iam::$acct:role/ai-env-egress-operator")" "$2"
  if [ -s "$1/reason_code" ]; then printf '    "StateReasonCode": "%s",\n' "$(cat "$1/reason_code")"; fi
  if [ -s "$1/reason" ]; then printf '    "StateReason": "%s",\n' "$(cat "$1/reason")"; fi
  printf '    "LastModified": "2026-10-01T10:00:00+00:00"\n}\n'
}
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
    printf '{"items": ['
    sep=
    if [ -f "$S/image/versions" ]; then
      while read -r v st; do
        [ -n "$v" ] || continue
        printf '%s{"imageVersion": "%s", "status": "%s", "state": "SUCCESSFUL"}' "$sep" "$v" "$st"
        sep=', '
      done < "$S/image/versions"
    fi
    printf ']}\n' ;;
  "lambda-microvms list-microvms")
    test -z "$query" || unsupported_query "$@"
    printf '{"items": ['
    sep=
    if [ -f "$S/vms" ]; then
      while read -r id v st; do
        [ -n "$id" ] || continue
        printf '%s{"microvmId": "%s", "imageVersion": "%s", "state": "%s"}' "$sep" "$id" "$v" "$st"
        sep=', '
      done < "$S/vms"
    fi
    printf ']}\n' ;;
  "lambda-microvms get-microvm-image-version")
    test -f "$S/image/state" || err ResourceNotFoundException GetMicrovmImageVersion "Image not found"
    if [ -f "$S/image/uri" ]; then
      printf '{"imageVersion": "%s", "codeArtifact": {"uri": "%s"}}\n' "$image_version" "$(cat "$S/image/uri")"
    else
      printf '{"imageVersion": "%s"}\n' "$image_version"
    fi ;;
  "lambda-core list-network-connectors")
    printf '{\n    "NetworkConnectors": ['
    sep=
    for d in "$S"/connectors/*; do
      [ -d "$d" ] || continue
      printf '%s\n        {\n            "Arn": "%s",\n            "Name": "%s",\n            "Id": "%s",\n            "Type": "VPC_EGRESS",\n            "State": "%s",\n            "LastModified": "2026-10-01T10:00:00+00:00"\n        }' \
        "$sep" "$(conn_arn "$d")" "${d##*/}" "$(conn_id "$d")" "$(cur_state "$d")"
      sep=,
    done
    printf '\n    ]\n}\n' ;;
  "lambda-core get-network-connector")
    d=$(conn_dir "$ident") || err ResourceNotFoundException GetNetworkConnector "The network connector $ident does not exist."
    conn_json "$d" "$(pop_state "$d")" ;;
  "lambda-core create-network-connector")
    test "${FAKE_AWS_CREATE_CONNECTOR:-}" != fail || err ServiceException CreateNetworkConnector "the fake refuses to create a connector"
    case "$cname" in
      ''|*/*|.*) err InvalidParameterValueException CreateNetworkConnector "bad name '$cname'" ;;
    esac
    test ! -e "$S/connectors/$cname" || err ResourceConflictException CreateNetworkConnector "The network connector $cname already exists."
    test -n "$config" && test -n "$role" || err InvalidParameterValueException CreateNetworkConnector "the fake wants --configuration and --operator-role"
    d="$S/connectors/$cname"
    mkdir -p "$d"
    printf '%s' "$config" > "$d/configuration"
    printf '%s' "$config" | sed -n 's/.*"SubnetIds": *\[ *"\([^"]*\)".*/\1/p' > "$d/subnet"
    printf '%s' "$config" | sed -n 's/.*"SecurityGroupIds": *\[ *"\([^"]*\)".*/\1/p' > "$d/sg"
    printf '%s' "$role" > "$d/role"
    if [ -f "$S/create-states" ]; then cp "$S/create-states" "$d/states"; else echo "PENDING ACTIVE" > "$d/states"; fi
    if [ -f "$S/create-delete-refusals" ]; then cp "$S/create-delete-refusals" "$d/delete-refusals"; fi
    if [ -f "$S/create-hold" ]; then touch "$d/hold"; fi
    conn_json "$d" "$(cur_state "$d")" ;;
  "lambda-core delete-network-connector")
    d=$(conn_dir "$ident") || err ResourceNotFoundException DeleteNetworkConnector "The network connector $ident does not exist."
    test "${FAKE_AWS_DELETE_CONNECTOR:-}" != fail || err ServiceException DeleteNetworkConnector "the fake refuses to delete a connector"
    refusals=$(cat "$d/delete-refusals" 2>/dev/null || echo 0)
    if [ "$refusals" -gt 0 ]; then
      echo $((refusals - 1)) > "$d/delete-refusals"
      err ResourceConflictException DeleteNetworkConnector "The network connector ${d##*/} is in use (the fake refuses $refusals more time(s))."
    fi
    json=$(conn_json "$d" DELETING)
    echo "${d##*/}" >> "$S/deleted"
    if [ -f "$d/delete-states" ]; then
      cp "$d/delete-states" "$d/states"
    else
      rm -rf "${d:?}"
    fi
    printf '%s\n' "$json" ;;
  "ec2 describe-instances")
    pid=$(file_or "$S/proxy/id" i-0123456789abcdef0)
    if [ "$instance" != "$pid" ] || [ ! -s "$S/proxy/state" ]; then
      err InvalidInstanceID.NotFound DescribeInstances "The instance ID '$instance' does not exist"
    fi
    printf '{\n    "Reservations": [\n        {\n            "Instances": [\n                {\n                    "InstanceId": "%s",\n                    "State": {\n                        "Name": "%s"\n                    },\n                    "PrivateIpAddress": "10.42.0.10"\n                }\n            ]\n        }\n    ]\n}\n' \
      "$pid" "$(cat "$S/proxy/state")" ;;
  "ec2 describe-network-interfaces")
    want=${filters#Name=subnet-id,Values=}
    if [ -z "$filters" ] || [ "$want" = "$filters" ]; then
      echo "fake aws: describe-network-interfaces wants --filters Name=subnet-id,Values=<subnet>" >&2
      exit 2
    fi
    printf '{\n    "NetworkInterfaces": ['
    sep=
    if [ -f "$S/enis" ]; then
      while read -r eni ip sg subnet managed; do
        [ -n "$eni" ] && [ "$subnet" = "$want" ] || continue
        [ "$managed" != managed ] || [ "$include_managed" = 1 ] || continue
        printf '%s\n        {\n            "NetworkInterfaceId": "%s",\n            "SubnetId": "%s",\n            "PrivateIpAddress": "%s",\n            "PrivateIpAddresses": [\n                {\n                    "Primary": true,\n                    "PrivateIpAddress": "%s"\n                }\n            ],\n            "Groups": [\n                {\n                    "GroupId": "%s",\n                    "GroupName": "ai-env-vm-egress"\n                }\n            ],\n            "Status": "in-use",\n            "InterfaceType": "lambda"\n        }' \
          "$sep" "$eni" "$subnet" "$ip" "$ip" "$sg"
        sep=,
      done < "$S/enis"
    fi
    printf '\n    ]\n}\n' ;;
  "ec2 describe-vpc-block-public-access-options")
    mode=$(file_or "$S/bpa" off)
    case "$query" in
      VpcBlockPublicAccessOptions.InternetGatewayBlockMode) echo "$mode" ;;
      '') printf '{\n    "VpcBlockPublicAccessOptions": {\n        "AwsRegion": "eu-central-1",\n        "State": "default-state",\n        "InternetGatewayBlockMode": "%s"\n    }\n}\n' "$mode" ;;
      *) unsupported_query "$@" ;;
    esac ;;
  "ec2 describe-vpcs")
    tag=
    case "$filters" in
      '') ;;
      Name=tag:Project,Values=*) tag=${filters#Name=tag:Project,Values=} ;;
      *) echo "fake aws: unsupported describe-vpcs filter $filters" >&2; exit 2 ;;
    esac
    case "$query" in
      'Vpcs[].[VpcId,CidrBlock]') if [ -f "$S/vpcs" ]; then awk -v t="$tag" 'NF >= 2 && (t == "" || $3 == t) { print $1 "\t" $2 }' "$S/vpcs"; fi ;;
      *) unsupported_query "$@" ;;
    esac ;;
  "ec2 describe-vpc-block-public-access-exclusions")
    case "$query" in
      'VpcBlockPublicAccessExclusions[].[ResourceArn,InternetGatewayExclusionMode,State]') if [ -f "$S/bpa-exclusions" ]; then awk 'NF >= 3 { print $1 "\t" $2 "\t" $3 }' "$S/bpa-exclusions"; fi ;;
      *) unsupported_query "$@" ;;
    esac ;;
  "service-quotas get-service-quota")
    test "$service:$quota" = vpc:L-F678F1CE || err NoSuchResourceException GetServiceQuota "The request failed because the specified quota $quota does not exist for service $service."
    case "$query" in
      Quota.Value) file_or "$S/vpc-quota" 5.0; echo ;;
      *) unsupported_query "$@" ;;
    esac ;;
  "iam get-role")
    if [ "$role_name" != AWSServiceRoleForLambda ] || [ ! -f "$S/slr" ]; then
      err NoSuchEntity GetRole "The role with name $role_name cannot be found."
    fi
    case "$query" in
      Role.Arn) echo "arn:aws:iam::$acct:role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda" ;;
      *) unsupported_query "$@" ;;
    esac ;;
  "logs tail")
    printf '2026-10-01T10:00:00.123000+00:00 aienv 1790000000.123     41 10.42.1.17 TCP_TUNNEL/200 5120 CONNECT api.anthropic.com:443\n'
    printf '2026-10-01T10:00:01.456000+00:00 aienv 1790000001.456      0 10.42.1.17 TCP_DENIED/403 3900 CONNECT example.com:443\n' ;;
  *)
    echo "fake aws: unsupported command: $*" >&2
    exit 2 ;;
esac
